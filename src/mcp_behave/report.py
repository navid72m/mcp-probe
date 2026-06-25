"""Phase 0 reporter: a deliberately crude declared-vs-observed diff.
NOT the real Phase 2 engine -- just enough to make the spike's point land.
Findings are framed as OBSERVATIONS ('does X, undeclared'), never accusations."""
import json, os, sys
from .analyze import analyze

SENSITIVE = (".ssh", "id_rsa", "id_ed25519", ".env", ".aws", "credentials",
             ".netrc", "/etc/shadow", ".kube", ".docker/config")

def load(out_dir):
    with open(os.path.join(out_dir, "manifest.json")) as f:
        manifest = json.load(f)
    profile = analyze(os.path.join(out_dir, "trace.log"))
    return manifest, profile

def report(out_dir):
    manifest, profile = load(out_dir)
    descs = " ".join((t.get("description") or "").lower() for t in manifest)
    claims_local = any(w in descs for w in ("local", "offline", "no network"))
    findings = []

    for ip in profile["network_connects"]:
        sev = "HIGH" if claims_local else "INFO"
        note = " -- but a tool description claims local/offline operation" if claims_local else ""
        findings.append((sev, f"network egress to {ip}{note}"))

    for path in profile["files_opened"]:
        if any(s in path for s in SENSITIVE):
            findings.append(("HIGH", f"read a sensitive path: {path}"))

    print(f"\n  target tools: {', '.join(t['name'] for t in manifest)}")
    print(f"  declared scope hints: {'mentions local/offline' if claims_local else 'none'}")
    print("  " + "-" * 56)
    if not findings:
        print("  no declared-vs-observed deviations detected")
    for sev, msg in sorted(findings, key=lambda x: x[0]):
        icon = "[!]" if sev == "HIGH" else "[i]"
        print(f"  {icon} {sev:4} {msg}")
    print()
    return findings

if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("OUT_DIR", "/tmp/probe_out")
    report(out)
