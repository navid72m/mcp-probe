"""Unit tests for the push subcommand's payload mapper. No network calls."""
from __future__ import annotations

import json
import sys
from io import StringIO

import pytest

from mcp_behave import push


SAMPLE_REPORT = {
    "server_cmd": ["python", "-m", "mcp_server_fetch"],
    "manifest_sha256": "abc123def456",
    "declared": {
        "tools": ["fetch", "fetch_raw"],
        "resources": [],
        "prompts": [],
    },
    "observed": {
        "network_connects": ["93.184.216.34:443"],
        "files_opened": [],
    },
    "findings": [
        {"severity": "INFO", "message": "network egress to 93.184.216.34:443 (example.com)"},
        {"severity": "HIGH", "message": "read a sensitive path: /home/u/.ssh/id_rsa"},
        {"severity": "HIGH", "message": "declared surface changed since last run (was abc, now def) -- possible rug-pull"},
    ],
    "stats": {},
}


def test_classify_known_message_types():
    assert push._classify_finding("network egress to 1.2.3.4:443") == (
        "network_egress",
        "1.2.3.4:443",
    )
    assert push._classify_finding("read a sensitive path: /home/u/.ssh/id_rsa") == (
        "sensitive_file_read",
        "/home/u/.ssh/id_rsa",
    )
    type_, detail = push._classify_finding("declared surface changed since last run")
    assert type_ == "rug_pull"
    assert "declared surface" in detail
    assert push._classify_finding("something completely new") == (
        "other",
        "something completely new",
    )


def test_build_payload_maps_full_report():
    payload = push.build_payload(
        SAMPLE_REPORT,
        server_name="server-fetch",
        description="MCP fetch server",
        github_url="https://github.com/modelcontextprotocol/servers/tree/main/src/fetch",
        npm_package=None,
        author="Anthropic",
        category="network",
        transport="stdio",
    )

    assert payload["server"]["name"] == "server-fetch"
    assert payload["server"]["githubUrl"].endswith("/fetch")
    assert payload["server"]["category"] == "network"
    assert payload["server"]["transport"] == "stdio"
    assert payload["server"]["author"] == "Anthropic"

    assert payload["audit"]["manifestHash"] == "abc123def456"
    # has at least one HIGH -> exitCode 3, status findings
    assert payload["audit"]["exitCode"] == 3
    assert payload["audit"]["status"] == "findings"

    assert [t["name"] for t in payload["tools"]] == ["fetch", "fetch_raw"]

    types = [f["type"] for f in payload["findings"]]
    assert types == ["network_egress", "sensitive_file_read", "rug_pull"]
    sevs = [f["severity"] for f in payload["findings"]]
    assert sevs == ["info", "high", "high"]


def test_build_payload_no_findings_is_clean():
    quiet = dict(SAMPLE_REPORT, findings=[])
    payload = push.build_payload(
        quiet,
        server_name="server-fetch",
        description=None,
        github_url=None,
        npm_package=None,
        author=None,
        category=None,
        transport="stdio",
    )
    assert payload["audit"]["status"] == "clean"
    assert payload["audit"]["exitCode"] == 0
    assert payload["findings"] == []


def test_build_payload_defaults_name_from_server_cmd():
    payload = push.build_payload(
        SAMPLE_REPORT,
        server_name=None,
        description=None,
        github_url=None,
        npm_package=None,
        author=None,
        category=None,
        transport="stdio",
    )
    assert payload["server"]["name"] == "python -m mcp_server_fetch"


def test_dry_run_prints_payload_and_exits_zero(monkeypatch, capsys, tmp_path):
    f = tmp_path / "audit.json"
    f.write_text(json.dumps(SAMPLE_REPORT))
    rc = push.main([str(f), "--dry-run", "--server-name", "x"])
    assert rc == 0
    out = capsys.readouterr().out
    parsed = json.loads(out)
    assert parsed["server"]["name"] == "x"


def test_missing_token_returns_2(monkeypatch, tmp_path, capsys):
    f = tmp_path / "audit.json"
    f.write_text(json.dumps(SAMPLE_REPORT))
    monkeypatch.delenv("MCP_BEHAVE_TOKEN", raising=False)
    monkeypatch.delenv("MCP_BEHAVE_DASHBOARD_URL", raising=False)
    rc = push.main([str(f), "--dashboard-url", "https://example.com"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "--token" in err
