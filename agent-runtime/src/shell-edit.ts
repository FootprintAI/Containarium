// Detecting a shell command that writes files (#3107 item 1).
//
// A run that edits only through shell_exec (agent-box) or Codex's native shell
// would otherwise get no re-prompt for a missing final message. A shell
// command is free text, so this is a heuristic, and it is built to be
// conservative: it names only the unmistakable write forms, so a run that only
// reads is not told it "changed files".
//
// Counted: an output redirection (> >> >|) to anything but /dev/*, tee, sed -i
// / perl -i, rm, mv, cp, touch, install, truncate, patch, git apply|mv|rm.
// Not counted: reads, searches, builds and test runs, package installs, mkdir
// and ln, and anything that writes through a program we cannot see into
// (python script.py, make, npm run build). Those runs fall back to the old
// behaviour, a failure with the reason in the journal. Text inside quotes is
// ignored, so `grep '>' f` and `echo "a > b"` are not writes.
//
// The cost of a miss is the pre-#2513 behaviour; the cost of a false positive
// is one extra, harmless question to a run that had no final message and
// would have failed anyway. That asymmetry is why the list stays short.

const WRITE_COMMANDS: ReadonlySet<string> = new Set(["tee", "rm", "mv", "cp", "touch", "install", "truncate", "patch"]);
const GIT_WRITE_SUBCOMMANDS: ReadonlySet<string> = new Set(["apply", "mv", "rm"]);
const WRAPPERS: ReadonlySet<string> = new Set(["sudo", "env", "command", "nohup", "time"]);

export function shellCommandWritesFiles(command: string): boolean {
  const script = unwrapShell(command.trim());
  const bare = blankQuoted(script);
  if (hasFileRedirect(bare)) return true;
  for (const segment of bare.split(/&&|\|\||[;&|\n(){}]/)) {
    if (segmentWrites(segment.trim().split(/\s+/))) return true;
  }
  return false;
}

// unwrapShell peels `bash -lc '<script>'` (how Codex records its commands).
function unwrapShell(command: string): string {
  const m = /^(?:\S*\/)?(?:ba|z|da)?sh\s+-[a-z]*c\s+([\s\S]+)$/.exec(command);
  if (!m) return command;
  const rest = (m[1] ?? "").trim();
  const q = rest[0];
  return (q === "'" || q === '"') && rest.endsWith(q) && rest.length >= 2 ? rest.slice(1, -1) : rest;
}

// blankQuoted empties quoted strings so their contents cannot look like syntax.
function blankQuoted(s: string): string {
  return s.replace(/'[^']*'/g, "''").replace(/"(?:\\.|[^"\\])*"/g, '""');
}

function hasFileRedirect(s: string): boolean {
  const cleaned = s
    .replace(/\d*>&\d*-?/g, " ") // 2>&1
    .replace(/(?:&>>?|\d*>>?\|?)\s*\/dev\/\S*/g, " "); // > /dev/null, 2>/dev/null, &> /dev/null
  return /(?<![=-])>/.test(cleaned);
}

function segmentWrites(words: string[]): boolean {
  let i = 0;
  while (i < words.length && (/^\w+=/.test(words[i] ?? "") || WRAPPERS.has(words[i] ?? ""))) i++;
  const cmd = (words[i] ?? "").replace(/^.*\//, "");
  const args = words.slice(i + 1);
  if (WRITE_COMMANDS.has(cmd)) return true;
  if (cmd === "sed") return args.some((a) => a === "--in-place" || a.startsWith("--in-place=") || /^-[a-zA-Z]*i/.test(a));
  if (cmd === "perl") return args.some((a) => /^-[a-zA-Z]*i/.test(a));
  if (cmd === "git") return GIT_WRITE_SUBCOMMANDS.has(args.find((a) => !a.startsWith("-")) ?? "");
  return false;
}
