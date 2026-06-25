"""mcp-behave: does an MCP server behave as it declares?

Single-command entry point. Orchestrates the pipeline that run.sh used to:
  1. probe   -- run the server under strace, capture manifest + syscall trace
  2. report  -- analyze the trace and print the declared-vs-observed diff
                (report.py calls analyze() internally, so there's no separate
                 analyze step here)

This is a thin orchestrator. It does NOT reimplement probe/analyze/report --
it calls them. Keep it that way.
"""
import argparse, asyncio, os, sys

# These modules live alongside this file in the mcp_behave package.
from . import probe as probe_mod
from . import report as report_mod

PTRACE_HINT = """
mcp-behave couldn't trace the target server.

If you're running in Docker, strace needs the ptrace capability. Add:
    --cap-add=SYS_PTRACE
e.g.  docker run --rm --cap-add=SYS_PTRACE mcp-behave <server-command>

If you're on Linux directly and still see this, your environment may restrict
ptrace (check /proc/sys/kernel/yama/ptrace_scope, or run under sudo).
"""


def _looks_like_ptrace_failure(exc: BaseException) -> bool:
    """The strace exec failure surfaces as an MCP 'Connection closed' (the server
    never came up) or a permission error. We can't always introspect the cause
    cleanly through the async stack, so match on the common signatures."""
    text = repr(exc).lower() + str(exc).lower()
    return any(s in text for s in
               ("connection closed", "permission denied", "ptrace", "exec"))


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="mcp-behave",
        description="Runtime behavioral auditor for MCP servers. "
                    "Runs a server under strace, then compares what it "
                    "DECLARED against what it actually DID.",
    )
    parser.add_argument(
        "server_command", nargs=argparse.REMAINDER,
        help="The MCP server to audit, e.g. `python -m mcp_server_fetch` "
             "or `python targets/leaky_server.py`.",
    )
    parser.add_argument(
        "--out-dir", default=os.environ.get("OUT_DIR", "/tmp/mcp_behave_out"),
        help="Where to write manifest.json and trace.log (default: %(default)s).",
    )
    args = parser.parse_args(argv)

    if not args.server_command:
        parser.error("no server command given. "
                     "Example: mcp-behave python -m mcp_server_fetch")

    os.environ["OUT_DIR"] = args.out_dir  # probe/report read this

    # --- Stage 1: observe ---
    print("=== STEP 1: observe (strace) ===")
    try:
        asyncio.run(probe_mod.run(args.server_command))
    except SystemExit:
        raise
    except BaseException as exc:  # asyncio TaskGroup raises ExceptionGroup
        if _looks_like_ptrace_failure(exc):
            print(PTRACE_HINT, file=sys.stderr)
            return 2
        # Unknown failure: show it plainly rather than a 40-line async stack.
        print(f"\nmcp-behave: probe failed: {exc}", file=sys.stderr)
        return 1

    # --- Stage 2: analyze + diff (report does both) ---
    print("=== STEP 2: declared-vs-observed diff ===")
    findings = report_mod.report(args.out_dir)

    # Exit non-zero if any HIGH findings, so it's CI-friendly.
    high = [f for f in findings if f[0] == "HIGH"]
    return 3 if high else 0


if __name__ == "__main__":
    sys.exit(main())