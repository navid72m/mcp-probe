"""Phase 0 probe: run a stdio MCP server under strace, exercise every tool with
synthesized inputs, and record (a) the server's self-declared manifest and
(b) the raw syscall trace of what it actually did.

This answers the only Phase 0 question: can we get accurate behavioral ground
truth out of an MCP server at all? It makes NO judgements -- see report.py."""
import asyncio, json, os, sys
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

OUT_DIR   = os.environ.get("OUT_DIR", "/tmp/probe_out")
TRACE_FILE = os.path.join(OUT_DIR, "trace.log")
MANIFEST   = os.path.join(OUT_DIR, "manifest.json")
SYSCALLS   = "openat,connect,execve,sendto"

def synth_args(schema: dict) -> dict:
    """Synthesize ONE plausible-and-valid input per field from a JSON schema.

    Strategy (first match wins, per property):
      1. JSON Schema `format` (uri, email, ipv4, date-time, ...) -- standards-based.
      2. Key-name heuristics (url, path, query, ...) -- pragmatic; many MCP tools
         don't set `format` but name fields obviously.
      3. Type-based default -- the original spike behavior, as a safety net.

    Goal is NOT coverage or fuzzing -- just inputs realistic enough that the tool
    actually runs (e.g. a `url` field gets a real URL) so we can observe behavior.
    A constrained `enum` is honored when present (first value), since random
    strings would be rejected outright.
    Phase 2+ may swap this for hypothesis-jsonschema if a schema defeats heuristics.
    """
    # Benign, obviously-synthetic values. example.com / example.org are reserved
    # by RFC 2606 for exactly this; using them keeps the probe's own traffic honest.
    FORMAT_VALUES = {
        "uri": "http://example.com/",
        "url": "http://example.com/",
        "iri": "http://example.com/",
        "email": "probe@example.com",
        "idn-email": "probe@example.com",
        "hostname": "example.com",
        "ipv4": "192.0.2.1",          # RFC 5737 documentation range
        "ipv6": "2001:db8::1",        # RFC 3849 documentation range
        "date-time": "2026-01-01T00:00:00Z",
        "date": "2026-01-01",
        "time": "00:00:00Z",
        "uuid": "00000000-0000-0000-0000-000000000000",
    }
    # Substring -> value. Checked against the lowercased property name.
    KEYNAME_HINTS = (
        ("url", "http://example.com/"),
        ("uri", "http://example.com/"),
        ("link", "http://example.com/"),
        ("href", "http://example.com/"),
        ("endpoint", "http://example.com/"),
        ("path", "/tmp/probe-canary.txt"),
        ("file", "/tmp/probe-canary.txt"),
        ("dir", "/tmp"),
        ("email", "probe@example.com"),
        ("host", "example.com"),
        ("query", "probe-canary"),
        ("search", "probe-canary"),
        ("text", "probe-canary"),
        ("name", "probe-canary"),
    )
    TYPE_DEFAULTS = {"string": "canary-input", "integer": 1, "number": 1.0,
                     "boolean": True, "array": [], "object": {}}

    def synth_one(key: str, spec: dict):
        spec = spec or {}
        # 0. Honor enum constraints first -- anything else would be rejected.
        if isinstance(spec.get("enum"), list) and spec["enum"]:
            return spec["enum"][0]
        # 1. Explicit JSON Schema format.
        fmt = spec.get("format")
        if fmt in FORMAT_VALUES:
            return FORMAT_VALUES[fmt]
        # 2. Key-name heuristics (only meaningful for string-ish fields).
        if spec.get("type", "string") == "string":
            k = key.lower()
            for needle, value in KEYNAME_HINTS:
                if needle in k:
                    return value
        # 3. Type default.
        return TYPE_DEFAULTS.get(spec.get("type", "string"), "canary-input")

    return {key: synth_one(key, spec)
            for key, spec in (schema or {}).get("properties", {}).items()}
async def run(server_cmd: list[str]):
    os.makedirs(OUT_DIR, exist_ok=True)
    # Wrap the real server in strace. The MCP SDK speaks stdio to strace, which
    # passes it through transparently while logging syscalls to TRACE_FILE.
    strace_cmd = ["strace", "-f", "-qq", "-e", f"trace={SYSCALLS}",
                  "-o", TRACE_FILE, *server_cmd]
    params = StdioServerParameters(command=strace_cmd[0], args=strace_cmd[1:],
                                   env={**os.environ})
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = (await session.list_tools()).tools
            manifest = [{"name": t.name, "description": t.description,
                         "inputSchema": t.inputSchema} for t in tools]
            with open(MANIFEST, "w") as f:
                json.dump(manifest, f, indent=2)
            print(f"[probe] discovered {len(tools)} tool(s): "
                  f"{', '.join(t.name for t in tools)}")
            for t in tools:
                args = synth_args(t.inputSchema)
                print(f"[probe] calling {t.name}({json.dumps(args)})")
                try:
                    await session.call_tool(t.name, args)
                except Exception as e:
                    print(f"[probe]   call raised: {e}")
    print(f"[probe] manifest -> {MANIFEST}")
    print(f"[probe] trace    -> {TRACE_FILE}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: probe.py <server-command> [args...]"); sys.exit(2)
    asyncio.run(run(sys.argv[1:]))
