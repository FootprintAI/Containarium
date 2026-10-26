import { describe, expect, it } from "vitest";
import { MAX_SHELL_COMMAND_BYTES, shellCommandWritesFiles } from "./shell-edit.js";

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
    // Cheap fixes (#3107 review): control keywords and git global options.
    ["if true; then rm a; fi", true],
    ["for f in *; do rm $f; done", true],
    ["git -C repo apply fix.patch", true],
    ["git -c core.x=1 -C repo rm a", true],
    ["git -C repo status", false],
    ["if true; then ls; fi", false],
    // An unterminated quote: what follows is still scanned.
    ['echo "oops > out.txt', true],
  ])("%j -> %s", (cmd, want) => {
    expect(shellCommandWritesFiles(cmd)).toBe(want);
  });

  // Known limits, pinned so a change to them is deliberate (see shell-edit.ts).
  it.each([
    ["xargs rm < list", false],
    ["find . -name '*.o' -delete", false],
    ["dd if=a of=b", false],
    ["git checkout -- f.go", false],
    ["bash -c 'bash -c \"rm a\"'", false],
    ["echo \\> not-a-redirect", true],
    ["echo $((1>2))", true],
  ])("known limit %j -> %s", (cmd, want) => {
    expect(shellCommandWritesFiles(cmd)).toBe(want);
  });

  it("returns promptly on a long hostile input and treats an over-long command as unreadable", () => {
    const hostile = '"\\'.repeat(100_000); // 200 KB
    const t0 = performance.now();
    expect(shellCommandWritesFiles(hostile)).toBe(false);
    expect(shellCommandWritesFiles(`rm a ${"x".repeat(MAX_SHELL_COMMAND_BYTES)}`)).toBe(false);
    expect(performance.now() - t0).toBeLessThan(200);
  });

  it("scans a hostile unterminated-quote input just under the cap in linear time", () => {
    const hostile = '"\\'.repeat(30_000); // quote, backslash, repeated: every quote starts a failing scan
    expect(hostile.length).toBeLessThan(MAX_SHELL_COMMAND_BYTES);
    const t0 = performance.now();
    expect(shellCommandWritesFiles(hostile)).toBe(false);
    expect(performance.now() - t0).toBeLessThan(200);
  });

  it("scans a long quoted-heavy command that is under the cap in linear time", () => {
    const cmd = `echo ${'"a\\\\" '.repeat(5_000)}> out.txt`;
    const t0 = performance.now();
    expect(shellCommandWritesFiles(cmd)).toBe(true);
    expect(performance.now() - t0).toBeLessThan(200);
  });
});
