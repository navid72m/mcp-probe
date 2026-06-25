"""`mcp-behave push`: upload a JSON audit result to an mcp-behave dashboard.

Reads JSON in the shape produced by `mcp-behave --json` (see report.report_json),
maps it to the dashboard's POST /api/audits payload, and submits with a Bearer
token. Stdlib-only (urllib) -- no extra runtime dependency.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from typing import Any

from . import __version__


def _classify_finding(msg: str) -> tuple[str, str]:
    """Map mcp-behave's free-text finding message to (type, detail) for the
    dashboard schema. Unknown shapes fall through as ('other', msg)."""
    if msg.startswith("network egress to "):
        return "network_egress", msg[len("network egress to ") :]
    if msg.startswith("read a sensitive path: "):
        return "sensitive_file_read", msg[len("read a sensitive path: ") :]
    if msg.startswith("declared surface changed"):
        return "rug_pull", msg
    return "other", msg


def _read_input(path: str) -> dict[str, Any]:
    if path == "-":
        return json.load(sys.stdin)
    with open(path) as f:
        return json.load(f)


def build_payload(
    audit: dict[str, Any],
    *,
    server_name: str | None,
    description: str | None,
    github_url: str | None,
    npm_package: str | None,
    author: str | None,
    category: str | None,
    transport: str,
) -> dict[str, Any]:
    """Translate a `report_json` dict into the dashboard ingest payload."""
    server_cmd = audit.get("server_cmd") or []
    default_name = " ".join(server_cmd) if server_cmd else "unknown-server"
    name = server_name or default_name

    declared_tools = audit.get("declared", {}).get("tools", [])
    tools = [{"name": t, "description": ""} for t in declared_tools]

    findings_in = audit.get("findings", [])
    findings_out: list[dict[str, Any]] = []
    for f in findings_in:
        sev_raw = (f.get("severity") or "high").lower()
        sev = "high" if sev_raw == "high" else "info"
        msg = f.get("message") or ""
        type_, detail = _classify_finding(msg)
        findings_out.append(
            {
                "type": type_,
                "severity": sev,
                "description": msg,
                "detail": detail,
            }
        )

    has_high = any(f["severity"] == "high" for f in findings_out)
    status = "findings" if findings_out else "clean"
    exit_code = 3 if has_high else 0

    server_block: dict[str, Any] = {
        "name": name,
        "transport": transport,
        "category": category or "other",
    }
    if description is not None:
        server_block["description"] = description
    if github_url:
        server_block["githubUrl"] = github_url
    if npm_package:
        server_block["npmPackage"] = npm_package
    if author:
        server_block["author"] = author

    return {
        "server": server_block,
        "audit": {
            "version": __version__,
            "status": status,
            "exitCode": exit_code,
            "manifestHash": audit.get("manifest_sha256"),
        },
        "tools": tools,
        "findings": findings_out,
    }


def _post(url: str, token: str, payload: dict[str, Any], *, timeout: float = 30.0) -> tuple[int, dict[str, Any] | str]:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "authorization": f"Bearer {token}",
            "content-type": "application/json",
            "user-agent": f"mcp-behave/{__version__}",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            try:
                return resp.status, json.loads(raw)
            except json.JSONDecodeError:
                return resp.status, raw
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        try:
            return e.code, json.loads(raw)
        except json.JSONDecodeError:
            return e.code, raw


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mcp-behave push",
        description="Upload a JSON audit result to an mcp-behave dashboard.",
    )
    p.add_argument(
        "audit_json",
        nargs="?",
        default="-",
        help="Path to JSON file produced by `mcp-behave --json`. Use '-' for stdin (default).",
    )
    p.add_argument(
        "--dashboard-url",
        default=os.environ.get("MCP_BEHAVE_DASHBOARD_URL"),
        help="Base URL of the dashboard, e.g. https://mcp-behave.vercel.app. "
        "Falls back to $MCP_BEHAVE_DASHBOARD_URL.",
    )
    p.add_argument(
        "--token",
        default=os.environ.get("MCP_BEHAVE_TOKEN"),
        help="Bearer token minted at <dashboard>/settings. "
        "Falls back to $MCP_BEHAVE_TOKEN.",
    )
    p.add_argument(
        "--server-name",
        help="Canonical name for the audited server on the dashboard. "
        "Defaults to the joined server command from the audit JSON.",
    )
    p.add_argument(
        "--description",
        help="Server description (used only on first submission of a new server).",
    )
    p.add_argument("--github-url", help="GitHub URL for the server.")
    p.add_argument("--npm-package", help="npm package name, if applicable.")
    p.add_argument("--author", help="Server author.")
    p.add_argument(
        "--category",
        default="other",
        help="One of: local, network, database, other (default: other).",
    )
    p.add_argument(
        "--transport",
        default="stdio",
        help="Transport the audit ran against (default: stdio).",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the payload that would be sent and exit without POSTing.",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        audit = _read_input(args.audit_json)
    except (OSError, json.JSONDecodeError) as e:
        print(f"mcp-behave push: failed to read audit JSON: {e}", file=sys.stderr)
        return 2

    payload = build_payload(
        audit,
        server_name=args.server_name,
        description=args.description,
        github_url=args.github_url,
        npm_package=args.npm_package,
        author=args.author,
        category=args.category,
        transport=args.transport,
    )

    if args.dry_run:
        json.dump(payload, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0

    if not args.dashboard_url:
        print(
            "mcp-behave push: --dashboard-url or MCP_BEHAVE_DASHBOARD_URL is required",
            file=sys.stderr,
        )
        return 2
    if not args.token:
        print(
            "mcp-behave push: --token or MCP_BEHAVE_TOKEN is required "
            "(mint one at <dashboard>/settings)",
            file=sys.stderr,
        )
        return 2

    endpoint = args.dashboard_url.rstrip("/") + "/api/audits"
    status, body = _post(endpoint, args.token, payload)
    if 200 <= status < 300:
        print(json.dumps(body) if isinstance(body, dict) else body)
        return 0

    print(f"mcp-behave push: HTTP {status}", file=sys.stderr)
    if isinstance(body, dict):
        print(json.dumps(body, indent=2), file=sys.stderr)
    else:
        print(body, file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
