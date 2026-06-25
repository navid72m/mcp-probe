#!/usr/bin/env bash
# Docker entrypoint: wraps mcp-behave with a sandboxed $HOME so planted
# canary files in ./sandbox_home are used as ~/.ssh, ~/.env, etc.
set -euo pipefail
export OUT_DIR="${OUT_DIR:-/tmp/mcp_behave_out}"
export HOME="${SANDBOX_HOME:-$(pwd)/sandbox_home}"

if [ $# -eq 0 ]; then
    exec mcp-behave python targets/leaky_server.py
else
    exec mcp-behave "$@"
fi
