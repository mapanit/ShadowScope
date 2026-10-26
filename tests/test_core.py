import json
import subprocess

import pytest

from config import Config
from core.diff import diff_scans
from core.scope import ScopePolicy
from core.storage import Storage
from modules.recon.httpx_probe import HttpxProbe
from modules.vuln.nuclei_scan import NucleiScanner
from reports.summary import finding_summary
from scanner.api_docs import ApiDocsScanner
from scanner.extra_tools import (
    GowitnessScanner,
    TestSSLScanner as TLSConfigScanner,
    TLSXScanner,
)
from scanner.file_scan import FileScanner


def test_config_exposes_only_bug_bounty_marker_and_migrates_legacy_user_agent(tmp_path):
    config_file = tmp_path / "config.json"
    config_file.write_text(
        json.dumps({
            "user_agent": "old custom agent",
            "bug_bounty_header_value": "program-123",
        }),
        encoding="utf-8",
    )

    config = Config(str(config_file))

    assert config.get_http_headers == {"X-Bug-Bounty": "program-123"}
    assert "user_agent" not in config.as_dict()


@pytest.mark.parametrize("value", ["", "  ", "tag\r\nX-Injected: true"])
def test_config_rejects_invalid_bug_bounty_header_values(value):
    config = Config()
    config.set("bug_bounty_header_value", value)

    with pytest.raises(ValueError):
        config.get_http_headers


def test_scope_matches_domain_boundaries_and_explicit_roots():
    scope = ScopePolicy("example.com", "authorized.test")

    assert scope.allows("https://api.example.com:8443/path")
    assert scope.allows("authorized.test")
    assert not scope.allows("example.com.attacker.test")
    assert not scope.allows("notexample.com")


def test_scope_supports_ip_addresses():
    scope = ScopePolicy("127.0.0.1:5012")

    assert scope.allows("http://127.0.0.1:9000")
    assert not scope.allows("127.0.0.2")


def test_diff_reports_first_scan_and_new_findings(tmp_path):
    storage = Storage(tmp_path / "scans.sqlite")
    try:
        first_scan = storage.start_scan("example.com", "first.log", {})
        asset_id = storage.add_asset("example.com", "host", "api.example.com")
        storage.add_finding(
            first_scan, asset_id, "vuln", "high", "Existing issue", {}
        )
        storage.finish_scan(first_scan)

        first_diff = diff_scans(storage, "example.com", first_scan)
        assert first_diff["first_scan"] is True
        assert first_diff["counts"]["new_findings"] == 0

        second_scan = storage.start_scan("example.com", "second.log", {})
        storage.add_finding(
            second_scan, asset_id, "vuln", "high", "Existing issue", {}
        )
        storage.add_finding(
            second_scan, asset_id, "vuln", "critical", "New issue", {}
        )

        second_diff = diff_scans(storage, "example.com", second_scan)
        assert second_diff["counts"]["new_findings"] == 1
        assert second_diff["new_findings"][0]["title"] == "New issue"
    finally:
        storage.close()


def test_report_summary_counts_severity_and_uses_remediation():
    summary = finding_summary(
        [{
            "kind": "vuln",
            "severity": "HIGH",
            "title": "Exposed component",
            "data_json": json.dumps({
                "info": {"remediation": "Upgrade the component"}
            }),
        }],
        {"first_scan": True},
    )

    assert summary["by_severity"]["high"] == 1
    assert summary["findings"][0]["status"] == "baseline"
    assert summary["findings"][0]["recommendation"] == "Upgrade the component"


def test_httpx_receives_bug_bounty_header(monkeypatch):
    captured = {}

    def fake_run_tool(command, **kwargs):
        captured["command"] = command
        return '{"url":"https://example.com"}', ""

    monkeypatch.setattr("modules.recon.httpx_probe.run_tool", fake_run_tool)
    result = HttpxProbe(
        headers={"X-Bug-Bounty": "program-123"}
    ).probe(["example.com"])

    assert result["count"] == 1
    assert "-H" in captured["command"]
    header_index = captured["command"].index("-H")
    assert captured["command"][header_index + 1] == "X-Bug-Bounty: program-123"
    assert "User-Agent" not in " ".join(captured["command"])


def test_nuclei_receives_bug_bounty_header(monkeypatch):
    captured = {}

    def fake_run_tool(command, **kwargs):
        captured["command"] = command
        return "", ""

    monkeypatch.setattr("modules.vuln.nuclei_scan.run_tool", fake_run_tool)
    result = NucleiScanner(Config()).scan(
        "https://example.com", use_custom=False
    )

    assert result["total"] == 0
    assert "-H" in captured["command"]
    header_index = captured["command"].index("-H")
    assert captured["command"][header_index + 1] == (
        "X-Bug-Bounty: ShadowScope/2.0"
    )


def test_api_docs_extracts_openapi_metadata(tmp_path, monkeypatch):
    document = {
        "openapi": "3.0.0",
        "info": {"title": "Juice Shop API", "version": "1.0"},
        "paths": {"/api/items": {}, "/api/users": {}},
    }

    class Response:
        status_code = 200
        headers = {"Content-Type": "application/json"}

        @staticmethod
        def json():
            return document

    monkeypatch.setattr("scanner.api_docs.requests.get", lambda *a, **k: Response())
    result = ApiDocsScanner(scope=ScopePolicy("127.0.0.1:3000")).scan(
        "http://127.0.0.1:3000"
    )

    assert result["specs"][0]["title"] == "Juice Shop API"
    assert result["specs"][0]["path_count"] == 2
    assert result["errors"] == []


def test_api_docs_does_not_fetch_external_swagger_spec(monkeypatch):
    requested_urls = []

    class Response:
        def __init__(self, status_code, headers=None, text=""):
            self.status_code = status_code
            self.headers = headers or {}
            self.text = text

        def json(self):
            raise ValueError("not JSON")

    def fake_get(url, **_kwargs):
        requested_urls.append(url)
        if url.endswith("/api-docs"):
            return Response(301, {"Location": "/api-docs/"})
        if url.endswith("/api-docs/"):
            return Response(
                200,
                {"Content-Type": "text/html"},
                '<div id="swagger-ui"></div>',
            )
        if url.endswith("/swagger-initializer.js"):
            return Response(
                200,
                {"Content-Type": "application/javascript"},
                'url: "https://petstore.swagger.io/v2/swagger.json"',
            )
        return Response(404)

    monkeypatch.setattr("scanner.api_docs.requests.get", fake_get)
    result = ApiDocsScanner(scope=ScopePolicy("127.0.0.1:3000")).scan(
        "http://127.0.0.1:3000"
    )

    assert "http://127.0.0.1:3000/api-docs/" in result["docs_pages"]
    assert result["external_references_not_fetched"] == [
        "https://petstore.swagger.io/v2/swagger.json"
    ]
    assert all("petstore.swagger.io" not in url for url in requested_urls)


def test_optional_tool_scanners_restrict_target_to_scope(monkeypatch, tmp_path):
    scope = ScopePolicy("127.0.0.1:3000")
    captured = []

    def fake_run_tool(command, **kwargs):
        captured.append(command)
        if command[0] == "tlsx":
            return '{"host":"127.0.0.1","port":"3000"}\n', ""
        if command[0] == "testssl.sh":
            return "doesn't seem to be a TLS/SSL enabled server", ""
        return "", ""

    monkeypatch.setattr("scanner.extra_tools.run_tool", fake_run_tool)
    monkeypatch.setattr(
        "scanner.extra_tools.report_directory",
        lambda _target, _name: tmp_path,
    )

    assert TLSXScanner(scope).scan("http://127.0.0.1:3000")["records"]
    assert TLSConfigScanner(scope).scan(
        "http://127.0.0.1:3000"
    )["status"] == "not-tls"
    screenshot = GowitnessScanner(scope).scan("http://127.0.0.1:3000")
    assert screenshot["target"] == "http://127.0.0.1:3000"
    assert all(
        any("127.0.0.1" in part for part in command)
        for command in captured
    )

    with pytest.raises(ValueError, match="вне разрешённой области"):
        TLSXScanner(scope).scan("https://127.0.0.2:3000")


def test_file_scan_surfaces_gobuster_wildcard_errors(monkeypatch, tmp_path):
    wordlist = tmp_path / "common.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    monkeypatch.setattr(
        FileScanner, "_tool_available", staticmethod(lambda _name: True)
    )
    monkeypatch.setattr(
        "scanner.file_scan.subprocess.run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0],
            1,
            "",
            "Error: server returns status code 200 for non existing urls",
        ),
    )

    result = FileScanner().scan_with_gobuster(
        "http://127.0.0.1:3000", str(wordlist)
    )

    assert "error" in result
    assert "non existing urls" in result["error"]


def test_file_scan_retries_gobuster_with_detected_wildcard_length(
    monkeypatch, tmp_path
):
    wordlist = tmp_path / "common.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    calls = []
    monkeypatch.setattr(
        FileScanner, "_tool_available", staticmethod(lambda _name: True)
    )

    def fake_run(command, **_kwargs):
        calls.append(command)
        if len(calls) == 1:
            return subprocess.CompletedProcess(
                command,
                1,
                "",
                "Error: non existing urls return 200 (Length: 9984)",
            )
        return subprocess.CompletedProcess(
            command, 0, "/admin (Status: 200)\n", ""
        )

    monkeypatch.setattr("scanner.file_scan.subprocess.run", fake_run)
    result = FileScanner().scan_with_gobuster(
        "http://127.0.0.1:3000", str(wordlist)
    )

    assert len(calls) == 2
    assert calls[1][-2:] == ["--exclude-length", "9984"]
    assert result == {
        "found_files": ["/admin (Status: 200)"],
        "excluded_wildcard_length": 9984,
    }
