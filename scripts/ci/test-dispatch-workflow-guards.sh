#!/usr/bin/env bash
# Tests for the workflow_dispatch guards in sidecars.yml and
# containarium-daemon.yml (#3396, follow-up to #3344).
#
#  1. Every "Derive image tags" step is executed for real with GITHUB_OUTPUT
#     pointed at a temp file: a malicious dispatched version must fail the step
#     and write nothing; a valid dispatched version and a real tag push must pass.
#  3. In every publishing job, the scan runs before publish and sign, and blocks
#     (#3578); mutated copies must fail this check.
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

# 3. Scan before publish (#3578): in every job that publishes, the image is
#    built into the job's own scan registry, scanned with a blocking Trivy
#    step, and only then copied to GHCR and signed. A mutated copy of each
#    workflow (scan made non-blocking, or moved after publish) must fail, so a
#    green check here cannot be a check that never looks.
STEP_RE = re.compile(r"^      - name: (.+?)\s*$")
JOB_RE = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$")

def job_steps(text):
    """Map job name -> list of (step name, block text), in file order."""
    jobs, cur, step = {}, None, None
    for ln in text.split("\n"):
        jm = JOB_RE.match(ln)
        if jm:
            cur, step = jm.group(1), None
            jobs[cur] = []
            continue
        if cur is None:
            continue
        sm = STEP_RE.match(ln)
        if sm:
            step = [sm.group(1), []]
            jobs[cur].append(step)
        elif step is not None:
            step[1].append(ln)
    return {j: [(n, "\n".join(b)) for n, b in steps] for j, steps in jobs.items()}

def order_errors(name, text):
    errs = []
    for job, steps in job_steps(text).items():
        names = [n for n, _ in steps]
        pub = [i for i, n in enumerate(names) if n.startswith("Publish the scanned image to GHCR")]
        # A publishing job is one that pushes or signs. Identified by what it does,
        # not by the new step name, so an unmigrated job cannot pass by omission.
        publishes = any("push: ${{" in b or "sign-image" in b or "imagetools create" in b
                        for _, b in steps)
        if not publishes:
            continue  # a job that does not publish has nothing to order
        if not pub:
            errs.append(f"{name}:{job}: publishes without a 'Publish the scanned image to GHCR' step after the scan")
            continue
        sign = [i for i, n in enumerate(names) if n.startswith("Sign and verify the image")]
        scan = [i for i, n in enumerate(names) if "Trivy" in n and "before publish" in n]
        build = [i for i, n in enumerate(names) if n.startswith("Build ")]
        where = f"{name}:{job}"
        if not scan:
            errs.append(f"{where}: publishes with no blocking scan named '... before publish'")
            continue
        s = scan[0]
        if not (build and build[0] < s):
            errs.append(f"{where}: image is not built before the scan")
        if not (s < pub[0] and (not sign or pub[0] < sign[0])):
            errs.append(f"{where}: publish/sign does not come after the scan")
        if "exit-code: '1'" not in steps[s][1]:
            errs.append(f"{where}: pre-publish scan is not blocking (exit-code must be '1')")
        for n, b in steps[:s]:
            if "push: ${{" in b or "imagetools create" in b:
                errs.append(f"{where}: step '{n}' pushes before the scan")
        if build and "push: true" not in steps[build[0]][1]:
            errs.append(f"{where}: build does not push to the scan registry only (push: true)")
    return errs

def mutate_each(text, fn):
    return fn(text)

if os.environ.get("SKIP_SCAN_ORDER") != "1":
    for name in FILES:
        text = open(os.path.join(root, ".github/workflows", name)).read()
        found = order_errors(name, text)
        for e in found:
            err("scan-before-publish: " + e)
        if not found and not job_steps(text):
            err(f"{name}: no jobs parsed")
        # Mutation checks: each must be caught.
        m_block = text.replace("exit-code: '1'", "exit-code: '0'", 1)
        if not order_errors(name + "(mutant: non-blocking)", m_block) and m_block != text:
            err(f"{name}: mutant with a non-blocking scan was not caught")
        m_name = text.replace("(image, before publish)", "(image)", 1)
        if not order_errors(name + "(mutant: unnamed scan)", m_name) and m_name != text:
            err(f"{name}: mutant with no 'before publish' scan was not caught")
        # Mutant: the job's Sign step moved ahead of its Publish step. Spliced by
        # position, so the mutation is asserted to have happened, not assumed.
        pub_at = text.find("      - name: Publish the scanned image to GHCR")
        sign_at = text.find("      - name: Sign and verify the image", pub_at)
        if pub_at < 0 or sign_at < 0:
            err(f"{name}: no Publish/Sign pair to mutate")
            continue
        m = re.search(r"\n  [A-Za-z0-9_-]+:\s*\n|\n\S", text[sign_at:])
        sign_end = sign_at + (m.start() + 1 if m else len(text[sign_at:]))
        m_order = text[:pub_at] + text[sign_at:sign_end] + text[pub_at:sign_at] + text[sign_end:]
        if m_order == text:
            err(f"{name}: sign-before-publish mutant did not change the file")
        elif not order_errors(name + "(mutant: sign before publish)", m_order):
            err(f"{name}: mutant with sign before publish was not caught")

if not fail:
    print("ok: sidecars.yml and containarium-daemon.yml dispatch guards")
sys.exit(fail)
PY
