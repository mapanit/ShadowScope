"""Discover in-scope OpenAPI/Swagger documents and Swagger UI pages."""
import json
import re
from urllib.parse import urljoin, urlsplit

import requests

from core.scope import ScopePolicy


class ApiDocsScanner:
    CANDIDATE_PATHS = (
        "/openapi.json",
        "/swagger.json",
        "/v3/api-docs",
        "/api-docs",
        "/api-docs/",
    )
    SPEC_URL_PATTERN = re.compile(r"""\burl\s*:\s*["']([^"']+)["']""")

    def __init__(
        self,
        timeout: int = 5,
        headers: dict[str, str] | None = None,
        scope: ScopePolicy | None = None,
    ):
        self.timeout = timeout
        self.headers = headers or {}
        self.scope = scope

    def scan(self, target: str) -> dict:
        base_url = target if "://" in target else f"http://{target}"
        parsed = urlsplit(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError(f"Некорректный URL для поиска API-документации: {target}")
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if self.scope:
            self.scope.require(origin)

        specs = {}
        docs_pages = set()
        external_references = set()
        errors = []
        urls = [urljoin(origin, path) for path in self.CANDIDATE_PATHS]

        for url in urls:
            response, final_url, external_url, error = self._get_same_origin(
                url, origin
            )
            if error:
                errors.append({"url": url, "error": error})
                continue
            if external_url:
                external_references.add(external_url)
                continue
            if response is None:
                continue
            if response.status_code != 200:
                continue

            document = self._parse_spec(response)
            if document:
                specs[final_url] = document
                continue

            content_type = response.headers.get("Content-Type", "").lower()
            body = response.text
            body_lower = body.lower()
            if "html" not in content_type or not (
                "swagger-ui" in body_lower
                or "swaggeruibundle" in body_lower
            ):
                continue

            docs_pages.add(final_url)
            initializer_url = urljoin(final_url, "swagger-initializer.js")
            initializer, initializer_url, external_url, error = (
                self._get_same_origin(initializer_url, origin)
            )
            if error:
                errors.append({"url": initializer_url, "error": error})
                continue
            if external_url:
                external_references.add(external_url)
                continue
            if initializer is None or initializer.status_code != 200:
                continue

            match = self.SPEC_URL_PATTERN.search(initializer.text)
            if not match:
                continue
            spec_url = urljoin(initializer_url, match.group(1))
            if not self._same_origin(spec_url, origin):
                external_references.add(spec_url)
                continue

            spec_response, spec_url, external_url, error = self._get_same_origin(
                spec_url, origin
            )
            if error:
                errors.append({"url": spec_url, "error": error})
                continue
            if external_url:
                external_references.add(external_url)
            elif spec_response is not None and spec_response.status_code == 200:
                document = self._parse_spec(spec_response)
                if document:
                    specs[spec_url] = document

        return {
            "target": origin,
            "specs": [
                {"url": url, **document}
                for url, document in sorted(specs.items())
            ],
            "docs_pages": sorted(docs_pages),
            "external_references_not_fetched": sorted(external_references),
            "errors": errors,
        }

    def _get_same_origin(self, url: str, origin: str):
        current_url = url
        for _ in range(4):
            if not self._same_origin(current_url, origin):
                return None, current_url, current_url
            if self.scope:
                self.scope.require(current_url)
            try:
                response = requests.get(
                    current_url,
                    headers=self.headers,
                    timeout=self.timeout,
                    allow_redirects=False,
                )
            except requests.RequestException as exc:
                return None, current_url, None, str(exc)

            if response.status_code not in {301, 302, 303, 307, 308}:
                return response, current_url, None, None
            location = response.headers.get("Location")
            if not location:
                return response, current_url, None, None
            current_url = urljoin(current_url, location)

        return None, current_url, None, "Слишком много перенаправлений"

    @staticmethod
    def _same_origin(url: str, origin: str) -> bool:
        parsed = urlsplit(url)
        expected = urlsplit(origin)
        return (
            parsed.scheme == expected.scheme
            and parsed.hostname == expected.hostname
            and parsed.port == expected.port
        )

    @staticmethod
    def _parse_spec(response: requests.Response) -> dict | None:
        try:
            document = response.json()
        except (ValueError, json.JSONDecodeError):
            return None
        if not isinstance(document, dict) or not (
            isinstance(document.get("openapi"), str)
            or isinstance(document.get("swagger"), str)
        ):
            return None
        info = document.get("info") or {}
        if not isinstance(info, dict):
            info = {}
        paths = document.get("paths")
        return {
            "format": "openapi" if "openapi" in document else "swagger",
            "version": document.get("openapi") or document.get("swagger"),
            "title": info.get("title"),
            "api_version": info.get("version"),
            "path_count": len(paths) if isinstance(paths, dict) else 0,
        }
