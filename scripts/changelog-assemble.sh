#!/usr/bin/env bash
# Changelog fragments (changelog.d/): validate them, or assemble them into
# CHANGELOG.md at release time.
#
#   scripts/changelog-assemble.sh --check
#   scripts/changelog-assemble.sh X.Y.Z [YYYY-MM-DD]
#   scripts/changelog-assemble.sh --self-test
#
# Run from the repository root (or set CHANGELOG_ROOT). See
# changelog.d/README.md for the fragment format.
set -euo pipefail

exec python3 -I - "$@" <<'PY'
import datetime, os, re, sys, tempfile, shutil, subprocess

CATEGORIES = ["added", "changed", "deprecated", "removed", "fixed",
              "security", "upgrading", "documentation"]
NAME = re.compile(r"^(\d+)\.(" + "|".join(CATEGORIES) + r")\.md$")
VERSION = re.compile(r"^\d+\.\d+\.\d+$")


def fragments(root):
    d = os.path.join(root, "changelog.d")
    out, errs = [], []
    if not os.path.isdir(d):
        return out, errs
    for name in sorted(os.listdir(d)):
        if name == "README.md" or name.startswith("."):
            continue
        m = NAME.match(name)
        if not m:
            errs.append(f"changelog.d/{name}: name must be <number>.<{'|'.join(CATEGORIES)}>.md")
            continue
        body = open(os.path.join(d, name), encoding="utf-8").read().strip("\n")
        if not body.strip():
            errs.append(f"changelog.d/{name}: empty")
        elif re.search(r"^(#{1,3}\s|## \[)", body, re.M):
            errs.append(f"changelog.d/{name}: must not contain headings")
        elif not body.startswith("- "):
            errs.append(f"changelog.d/{name}: entry must start with '- '")
        else:
            out.append((int(m.group(1)), m.group(2), name, body))
    return out, errs


def assemble(root, version, date):
    frs, errs = fragments(root)
    if errs:
        raise SystemExit("\n".join(errs))
    path = os.path.join(root, "CHANGELOG.md")
    lines = open(path, encoding="utf-8").read().split("\n")
    try:
        start = next(i for i, l in enumerate(lines) if l.strip() == "## [Unreleased]")
    except StopIteration:
        raise SystemExit("CHANGELOG.md has no '## [Unreleased]' heading")
    end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("## [")), len(lines))
    body = lines[start + 1:end]

    # Split the Unreleased body into (heading, lines) blocks; the text before
    # the first '### ' is the preamble.
    blocks = [[None, []]]
    for l in body:
        if l.startswith("### "):
            blocks.append([l[4:].strip(), []])
        else:
            blocks[-1][1].append(l)

    def trim(ls):
        while ls and not ls[-1].strip():
            ls.pop()
        return ls

    by_cat = {}
    for _, cat, _, text in sorted(frs):
        by_cat.setdefault(cat, []).append(text)
    for cat in CATEGORIES:
        if cat not in by_cat:
            continue
        heading = cat.capitalize()
        idx = max((i for i, b in enumerate(blocks) if b[0] == heading), default=None)
        if idx is None:
            blocks.append([heading, []])
            idx = len(blocks) - 1
        ls = trim(blocks[idx][1])
        if not ls:
            ls = [""]
        for text in by_cat[cat]:
            ls.extend(text.split("\n"))
        blocks[idx][1] = ls + [""]

    section = []
    for head, ls in blocks:
        if head is not None:
            section.append(f"### {head}")
        section.extend(ls)
    section = trim(section)
    if not any(l.strip() and not l.startswith("###") for l in section):
        raise SystemExit("nothing to release: [Unreleased] is empty and there are no fragments")

    new = lines[:start + 1] + ["", f"## [{version}] - {date}", ""] + \
        section + [""] + lines[end:]
    open(path, "w", encoding="utf-8").write("\n".join(new))
    for _, _, name, _ in frs:
        os.remove(os.path.join(root, "changelog.d", name))
    print(f"assembled {len(frs)} fragment(s) into [{version}]")


def self_test():
    fails = 0

    def case(name, ok):
        nonlocal fails
        print(("ok   " if ok else "FAIL ") + name)
        fails += 0 if ok else 1

    def tree(files, changelog):
        d = tempfile.mkdtemp()
        os.makedirs(os.path.join(d, "changelog.d"))
        open(os.path.join(d, "CHANGELOG.md"), "w").write(changelog)
        for n, c in files.items():
            open(os.path.join(d, "changelog.d", n), "w").write(c)
        return d

    base = "# Changelog\n\n## [Unreleased]\n\n### Added\n\n- old\n\n### Added\n\n- old2\n\n## [0.1.0] - 2026-01-01\n\n### Fixed\n\n- x\n"
    d = tree({"README.md": "doc", "2.fixed.md": "- b\n  more", "1.added.md": "- a"}, base)
    assemble(d, "0.2.0", "2026-02-02")
    out = open(os.path.join(d, "CHANGELOG.md")).read()
    case("empty Unreleased kept", "## [Unreleased]\n\n## [0.2.0] - 2026-02-02" in out)
    case("merged into last Added block", "- old2\n- a\n" in out)
    case("new Fixed heading from fragment", "### Fixed\n\n- b\n  more\n\n## [0.1.0]" in out)
    case("fragments deleted, README kept", sorted(os.listdir(os.path.join(d, "changelog.d"))) == ["README.md"])
    shutil.rmtree(d)

    for name, files in {
        "bad name": {"x.md": "- a"},
        "unknown category": {"1.misc.md": "- a"},
        "empty body": {"1.added.md": "\n"},
        "heading in body": {"1.added.md": "- a\n### Added"},
        "no bullet": {"1.added.md": "text"},
    }.items():
        d = tree(files, base)
        case(f"rejects {name}", bool(fragments(d)[1]))
        shutil.rmtree(d)

    d = tree({}, "# C\n\n## [Unreleased]\n\n## [0.1.0] - x\n")
    try:
        assemble(d, "0.2.0", "2026-02-02"); case("refuses empty release", False)
    except SystemExit:
        case("refuses empty release", True)
    shutil.rmtree(d)
    if fails:
        raise SystemExit(f"{fails} self-test case(s) failed")
    print("all self-test cases passed")


args = sys.argv[1:]
root = os.environ.get("CHANGELOG_ROOT", ".")
if args == ["--self-test"]:
    self_test()
elif args == ["--check"]:
    errs = fragments(root)[1]
    if errs:
        print("\n".join(errs), file=sys.stderr)
        raise SystemExit(1)
    print("changelog fragments ok")
elif 1 <= len(args) <= 2 and VERSION.match(args[0]):
    assemble(root, args[0], args[1] if len(args) == 2 else datetime.date.today().isoformat())
else:
    raise SystemExit("usage: changelog-assemble.sh --check | X.Y.Z [date] | --self-test")
PY
