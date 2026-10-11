"""Target-scope validation shared by scanners and the full pipeline."""
import ipaddress
from urllib.parse import urlsplit


def _host(value: str) -> str:
    raw = value.strip()
    if not raw:
        raise ValueError("Цель не может быть пустой")
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        pass
    parsed = urlsplit(raw if "://" in raw else f"//{raw}")
    hostname = parsed.hostname
    if not hostname:
        raise ValueError(f"Не удалось определить хост цели: {value}")
    hostname = hostname.rstrip(".").lower()
    try:
        return str(ipaddress.ip_address(hostname))
    except ValueError:
        try:
            return hostname.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError(f"Некорректное имя хоста: {value}") from exc


class ScopePolicy:
    """Allow the root target, its subdomains, and explicitly authorized roots."""

    def __init__(self, root: str, additional_roots: str | list[str] | None = None):
        self.root = _host(root)
        if isinstance(additional_roots, str):
            roots = [part.strip() for part in additional_roots.split(",") if part.strip()]
        else:
            roots = additional_roots or []
        self.allowed_roots = tuple(dict.fromkeys(
            [self.root, *(_host(item) for item in roots)]
        ))

    def allows(self, target: str) -> bool:
        host = _host(target)
        for root in self.allowed_roots:
            try:
                ipaddress.ip_address(root)
            except ValueError:
                if host == root or host.endswith(f".{root}"):
                    return True
            else:
                if host == root:
                    return True
        return False

    def require(self, target: str) -> str:
        if not self.allows(target):
            raise ValueError(
                f"Цель вне разрешённой области сканирования: {target}. "
                f"Разрешены {', '.join(self.allowed_roots)} и их поддомены."
            )
        return _host(target)

    def filter(self, targets: list[str]) -> tuple[list[str], list[str]]:
        accepted = []
        rejected = []
        for target in targets:
            try:
                self.require(target)
            except ValueError:
                rejected.append(target)
            else:
                accepted.append(target)
        return accepted, rejected
