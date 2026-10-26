import { describe, expect, it } from "vitest";
import { shellCommandWritesFiles } from "./shell-edit.js";

describe("shellCommandWritesFiles (#3107 item 1)", () => {
  it.each([
    ["echo hi > out.txt", true],
    ["echo hi >> out.txt", true],
    ["cat a b >out.txt", true],
    ["echo hi >| out.txt", true],
    ["printf x | tee out.txt", true],
    ["sed -i 's/a/b/' f.go", true],
    ["sed -n 1p f.go && sed --in-place s/a/b/ f.go", true],
    ["perl -pi -e 's/a/b/' f.go", true],
    ["rm -rf build", true],
    ["mv a b", true],
    ["cp a b", true],
    ["touch new.go", true],
    ["git apply fix.patch", true],
    ["patch -p1 < fix.patch", true],
    ["cd src && rm old.go", true],
    ["FOO=1 sudo rm old.go", true],
    ["cat <<EOF > f.txt\nhello\nEOF", true],
    // Codex wraps the script in bash -lc '...'.
    ["bash -lc 'echo hi > out.txt'", true],
    ["/bin/bash -lc \"sed -i s/a/b/ f.go\"", true],
    ["bash -lc 'ls -la'", false],
    // Reads, searches and output sent nowhere do not count.
    ["ls -la", false],
    ["cat f.go", false],
    ["grep -rn 'a > b' .", false],
    ['echo "x > y"', false],
    ["go test ./... 2>&1", false],
    ["go test ./... > /dev/null 2>&1", false],
    ["make 2>/dev/null", false],
    ["cmd &> /dev/null", false],
    ["git status && git diff", false],
    ["sed -n '1,5p' f.go", false],
    ["echo a => b", false],
    ["ps | grep rmdir", false],
    ["echo remove", false],
    ["", false],
  ])("%j -> %s", (cmd, want) => {
    expect(shellCommandWritesFiles(cmd)).toBe(want);
  });
});
