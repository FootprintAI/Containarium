#!/usr/bin/env bash
# Tests for the workflow_dispatch guards in sidecars.yml and
# containarium-daemon.yml (#3396, follow-up to #3344).
#
#  1. Every "Derive image tags" step is executed for real with GITHUB_OUTPUT
#     pointed at a temp file: a malicious dispatched version must fail the step
#     and write nothing; a valid dispatched version and a real tag push must pass.
#  2. Every publish/sign/scan condition that keys on the tag ref must also
#     require github.event_name == 'push', so a dispatch run on a tag ref
#     cannot publish.
# Never dispatches a workflow; reads the YAML as text (stdlib only).
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
exec python3 -I - "$root" <<'PY'
import os, re, subprocess, sys, tempfile

root = sys.argv[1]
FILES = ["sidecars.yml", "containarium-daemon.yml"]
TAGREF = "startsWith(github.ref, 'refs/tags/v')"
fail = 0

def err(msg):
    global fail
    fail = 1
    print("FAIL: " + msg)

def derive_blocks(text):
    """Yield the run script of every step named 'Derive image tags'."""
    lines = text.split("\n")
    for i, ln in enumerate(lines):
        if not re.match(r"\s*- name: Derive image tags\s*$", ln):
            continue
        j = i + 1
        while j < len(lines) and not re.match(r"\s*run: \|\s*$", lines[j]):
            j += 1
        base = len(lines[j]) - len(lines[j].lstrip())
        body = []
        for k in range(j + 1, len(lines)):
            s = lines[k]
            if s.strip() and len(s) - len(s.lstrip()) <= base:
                break
            body.append(s)
        yield "\n".join(body)

def run(script, event, version, ref):
    with tempfile.NamedTemporaryFile("r+") as out:
        env = {"PATH": os.environ["PATH"], "GITHUB_EVENT_NAME": event,
               "INPUT_VERSION": version, "GITHUB_REF": ref,
               "GITHUB_OUTPUT": out.name}
        p = subprocess.run(["bash", "-e", "-c", script], cwd=root, env=env,
                           capture_output=True, text=True)
        return p.returncode, open(out.name).read()

BAD = ["", "v0.61.0", "1.0", "1.0.0; echo x", "1.0.0$(id)", "1.0.0`id`",
       "1.0.0/../x", "1.0.0+build", "1.0.0\nversion=evil", "1.0.0\r\nx=y",
       "evil\n1.0.0"]
GOOD = ["0.61.0", "0.101.0-rc.1", "0.0.0-dryrun"]

for name in FILES:
    path = os.path.join(root, ".github/workflows", name)
    text = open(path).read()
    blocks = list(derive_blocks(text))
    if not blocks:
        err(f"{name}: no 'Derive image tags' step found")
    for n, script in enumerate(blocks):
        tag = f"{name} derive[{n}]"
        for v in BAD:
            rc, out = run(script, "workflow_dispatch", v, "refs/heads/main")
            if rc == 0 or out:
                err(f"{tag}: accepted dispatched version {v!r} (rc={rc}, output={out!r})")
        for v in GOOD:
            rc, out = run(script, "workflow_dispatch", v, "refs/heads/main")
            if rc != 0 or f"{v}" not in out:
                err(f"{tag}: refused valid dispatched version {v!r}")
        rc, out = run(script, "push", "", "refs/tags/v1.2.3")
        if rc != 0 or "1.2.3" not in out:
            err(f"{tag}: tag-push path broken (rc={rc})")
        rc, out = run(script, "push", "", "refs/tags/v1.2.3;id")
        if rc == 0:
            err(f"{tag}: accepted a malicious pushed tag name")
    for i, ln in enumerate(text.split("\n"), 1):
        if ln.lstrip().startswith("#") or TAGREF not in ln:
            continue
        if "github.event_name == 'push'" not in ln:
            err(f"{name}:{i}: tag-ref condition without event_name == 'push': {ln.strip()}")

if not fail:
    print("ok: sidecars.yml and containarium-daemon.yml dispatch guards")
sys.exit(fail)
PY
