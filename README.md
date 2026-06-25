# mcp-behave

**Runtime behavioral auditor for MCP servers.** Runs an MCP server under
`strace`, exercises every tool / resource / prompt it advertises, and then
compares what it *declared* against what it actually *did* — file reads,
network egress, subprocess execution.

Static scanners read tool descriptions. `mcp-behave` watches behavior.

## The idea in one contrast

`targets/leaky_server.py` and `targets/honest_server.py` advertise the
**identical** tool:

> `format_note` — "Formats a markdown note. Purely local text formatting."

A static scanner reads two harmless tools. `mcp-behave` sees the difference:

| Target          | network egress      | sensitive file read        | findings |
|-----------------|---------------------|----------------------------|----------|
| `honest_server` | none                | none                       | **0**    |
| `leaky_server`  | `93.184.216.34:80`  | `~/.ssh/id_rsa` (a canary) | **2 HIGH** |

The honest server producing **zero** findings matters as much as the leaky one
tripping two — false positives would kill credibility.

## Install

```bash
pip install mcp-behave
```

Requires Linux + `strace` for the syscall-trace backend. On macOS/Windows, use
the bundled `Dockerfile` (see below).

## Use

```bash
# Audit any stdio MCP server -- pass its launch command:
mcp-behave python -m mcp_server_fetch
mcp-behave npx -y @modelcontextprotocol/server-filesystem /tmp
mcp-behave uvx mcp-server-git

# Machine-readable output for CI:
mcp-behave --json --fail-on high python -m mcp_server_fetch

# Connect to an already-running remote server (manifest analysis only,
# no syscall trace possible):
mcp-behave --transport sse http://localhost:8000/sse
```

Exit codes: `0` clean, `3` findings at or above `--fail-on` threshold,
`2` strace/ptrace setup failed, `1` other error.

### Useful flags

- `--json` — emit findings as JSON on stdout.
- `--fail-on {never,info,high}` — severity that triggers exit code 3 (default `high`).
- `--no-dns` — skip reverse-DNS lookups (faster, offline-safe).
- `--timeout SECONDS` — per-call timeout (default 15).
- `--transport {stdio,sse,streamable-http}` — remote transports skip syscall tracing.
- `--out-dir PATH` — where `manifest.json` and `trace.log` are written.

## Push results to a dashboard

`mcp-behave push` uploads a JSON audit result to an
[mcp-behave dashboard](https://github.com/navid72m/mcp-behave-dashboard).

```bash
# 1. Sign in at https://<your-dashboard>.vercel.app/settings and mint a token.
export MCP_BEHAVE_DASHBOARD_URL=https://<your-dashboard>.vercel.app
export MCP_BEHAVE_TOKEN=mcpb_...

# 2. Audit something with --json and pipe it to push.
mcp-behave --json python -m mcp_server_fetch \
  | mcp-behave push --server-name server-fetch --category network

# Or save to a file first, then push.
mcp-behave --json python -m mcp_server_fetch > audit.json
mcp-behave push audit.json --server-name server-fetch --category network
```

Flags worth knowing:

- `--server-name NAME` — canonical name on the dashboard. Defaults to the joined
  server command from the audit JSON; usually you want to set this.
- `--description TEXT` — used the first time this server is submitted.
- `--github-url URL`, `--npm-package PKG`, `--author NAME` — optional server metadata.
- `--category {local,network,database,other}` — defaults to `other`.
- `--dry-run` — print the JSON payload that would be POSTed and exit.

The endpoint is rate-limited per token (20 req/min); `push` exits 1 on HTTP error
and prints the response body to stderr.

## What it detects

- **Undeclared network egress** — IP:port destinations reached during tool calls
  (reverse-DNS resolved in findings when available).
- **Sensitive-path reads** — `~/.ssh/*`, `~/.aws/*`, `~/.env`, `~/.netrc`, etc.
- **Rug-pull** — the declared manifest hash changes between runs of the same
  server (e.g. a tool's description silently changes after the user trusts it).
  Hashes persist under `$XDG_DATA_HOME/mcp-behave/manifests/`.

Findings are framed as observations ("does X, undeclared"), never accusations.

## Docker (works on macOS / Windows hosts)

```bash
docker build -t mcp-behave .
# default: runs the bundled leaky target so you can see findings immediately
docker run --rm --cap-add=SYS_PTRACE mcp-behave
# point at a real server
docker run --rm --cap-add=SYS_PTRACE mcp-behave python -m mcp_server_fetch
```

`--cap-add=SYS_PTRACE` is required for `strace` to attach inside the container.

The image bundles Node.js (for `npx` servers), `uv` (for `uvx` servers), and
sandbox canary files (`sandbox_home/`) mounted as `$HOME` so credential reads
are detectable.

## Development

```bash
pip install -e ".[test]"
pytest -v
```

CI runs on Ubuntu (strace is Linux-only); see `.github/workflows/ci.yml`.

## Known limits

- **Linux-only ground truth** via `strace`. eBPF/seccomp backend is on the
  roadmap — see [ROADMAP.md](ROADMAP.md).
- **stdio is the only transport with syscall tracing.** `sse` and
  `streamable-http` connect to a remote server we cannot trace; only manifest
  analysis and rug-pull detection apply there.
- **Input synthesis is heuristic** — JSON Schema `format`, key-name hints, and
  type defaults. Schema-coverage fuzzing (hypothesis-jsonschema) is roadmap.
- **AF_UNIX egress** isn't matched — a server exfiltrating over a unix domain
  socket would slip past the current network detection.
- **Single call per capability** — servers that misbehave only on specific
  inputs or after N calls may not be triggered.

## License

MIT. See [LICENSE](LICENSE).
