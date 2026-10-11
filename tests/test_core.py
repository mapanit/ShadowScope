import json

import pytest

from config import Config
from core.diff import diff_scans
from core.scope import ScopePolicy
from core.storage import Storage
from modules.recon.httpx_probe import HttpxProbe
from modules.vuln.nuclei_scan import NucleiScanner
from reports.summary import finding_summary


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
