"""Phase 1 analyzer: parse the strace log into a structured behavioral profile.
Pure observation -- lists what the server touched. No allowlist, no verdict yet."""
import re, sys, json, os

OPENAT = re.compile(r'openat\([^,]+,\s*"([^"]+)"')
# matches both: sin_addr=inet_addr("1.2.3.4")  and  sin6_addr=inet_pton(AF_INET6, "::1", ...)
CONNECT = re.compile(r'connect\(\d+,\s*\{sa_family=AF_INET6?,\s*'
                     r'sin6?_port=htons\((\d+)\),\s*sin6?_addr=inet_'
                     r'(?:addr|pton)\((?:[^,]+,\s*)?"([^"]+)"')
EXECVE = re.compile(r'execve\("([^"]+)"')
# DEFERRED (v2): AF_UNIX egress and alternate sockaddr renderings are not matched.
# A server exfiltrating over a unix domain socket would slip past CONNECT today.

# Substrings that mark a path as runtime/library noise, not behaviorally interesting.
# NOTE: tuned for the spike's Docker+venv layout. Real servers vary (Node, system
# Python, /app, /opt, Nix store), so this is now augmentable via $PROBE_NOISE_EXTRA
# (colon-separated substrings) without editing source. Keep additions conservative:
# over-filtering hides real behavior, under-filtering creates false positives.
NOISE_SUBSTR = ("/site-packages/", "/__pycache__/", "/.venv/", "/usr/", "/lib/",
                "/lib64/", "/proc/", "/sys/", "/dev/", "/etc/ld.so", "dist-info",
                "pyvenv.cfg", "/tmp/probe_trace",
                # common cross-runtime additions:
                "/node_modules/", "/.cache/", "/opt/homebrew/", "/nix/store/",
                "/.nvm/", "/.npm/", "/.pyenv/")
NOISE_SUFFIX = (".pyc", ".so", ".py._pth", ".node", ".dylib")
# Unix sockets / non-routable destinations we don't care about in the spike.
NET_NOISE = ("127.0.0.1", "::1", "0.0.0.0")

# Allow ad-hoc noise substrings per-run without editing source, for unfamiliar layouts.
_EXTRA = tuple(s for s in os.environ.get("PROBE_NOISE_EXTRA", "").split(":") if s)
NOISE_SUBSTR = NOISE_SUBSTR + _EXTRA

def interesting_file(path: str) -> bool:
    if any(s in path for s in NOISE_SUBSTR): return False
    if path.endswith(NOISE_SUFFIX): return False
    return True

def interesting_net(ip: str) -> bool:
    return not any(ip.startswith(n) for n in NET_NOISE)

def real_port(entry: str) -> bool:
    # Drop ":0" pseudo-destinations: connect() calls captured mid-setup or on
    # non-TCP sockets render port 0. They duplicate real "IP:443" findings as
    # noise. Keep only entries with a real (non-zero) port.
    return not entry.endswith(":0")

def analyze(path: str) -> dict:
    files, nets, execs = set(), set(), set()
    filtered_files = 0  # how many openat hits the noise filter removed
    with open(path, errors="replace") as f:
        for line in f:
            if (m := OPENAT.search(line)):
                if interesting_file(m.group(1)):
                    files.add(m.group(1))
                else:
                    filtered_files += 1
            if (m := CONNECT.search(line)) and interesting_net(m.group(2)):
                nets.add(f"{m.group(2)}:{m.group(1)}")
            if (m := EXECVE.search(line)):
                execs.add(m.group(1))
    return {"files_opened": sorted(files),
            "network_connects": sorted(n for n in nets if real_port(n)),
            "subprocesses": sorted(execs),
            # provenance: lets a caller distinguish "genuinely clean" from
            # "noise filter ate everything" when a real server yields 0 findings.
            "_meta": {"files_filtered_as_noise": filtered_files}}

if __name__ == "__main__":
    tf = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("TRACE_FILE", "/tmp/probe_trace.log")
    print(json.dumps(analyze(tf), indent=2))