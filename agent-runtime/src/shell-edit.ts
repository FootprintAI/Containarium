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
// Known limits (#3107 review). Misses: git checkout/restore/reset/clean,
// xargs rm, find -delete / -exec rm, dd of=, a bash -c nested inside bash -c,
// backtick and $( ) substitutions, and any interpreter that writes from its own
// code (python, node, make). False positives: a backslash-escaped `>`,
// `$((1>2))` and `[[ 1 > 2 ]]` read as redirections, and here-document bodies
// are scanned as if they were commands. A command over MAX_SHELL_COMMAND_BYTES
// is not scanned at all (reported as not writing), which bounds the work done
// on the event loop for hostile input.
//
// The cost of a miss is the pre-#2513 behaviour; the cost of a false positive
// is one extra, harmless question to a run that had no final message and
// would have failed anyway. That asymmetry is why the list stays short.

const WRITE_COMMANDS: ReadonlySet<string> = new Set(["tee", "rm", "mv", "cp", "touch", "install", "truncate", "patch"]);
const GIT_WRITE_SUBCOMMANDS: ReadonlySet<string> = new Set(["apply", "mv", "rm"]);
const WRAPPERS: ReadonlySet<string> = new Set(["sudo", "env", "command", "nohup", "time"]);
// Shell keywords that precede the command word of a segment.
const KEYWORDS: ReadonlySet<string> = new Set(["then", "do", "else", "elif", "if", "while", "until", "!"]);
// git global options that take a separate value.
const GIT_VALUE_OPTIONS: ReadonlySet<string> = new Set(["-C", "-c", "--git-dir", "--work-tree"]);

// MAX_SHELL_COMMAND_BYTES: longer commands are not scanned (see above).
export const MAX_SHELL_COMMAND_BYTES = 64 * 1024;

export function shellCommandWritesFiles(command: string): boolean {
  if (command.length > MAX_SHELL_COMMAND_BYTES) return false;
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
// A single linear scan (a regex for an escaped double-quoted string backtracks
// quadratically on an unterminated quote); an unterminated quote is left as
// it is, so what follows it is still read.
function blankQuoted(s: string): string {
  let out = "";
  let i = 0;
  while (i < s.length) {
    const c = s[i];
    if (c === "'" || c === '"') {
      let j = i + 1;
      while (j < s.length && s[j] !== c) j += c === '"' && s[j] === "\\" ? 2 : 1;
      if (j < s.length) {
        out += c + c;
        i = j + 1;
        continue;
      }
      // Unterminated: keep the rest as it is. Rescanning from the next quote
      // would make a run of unterminated quotes quadratic.
      return out + s.slice(i);
    }
    out += c;
    i++;
  }
  return out;
}

function hasFileRedirect(s: string): boolean {
  const cleaned = s
    .replace(/\d*>&\d*-?/g, " ") // 2>&1
    .replace(/(?:&>>?|\d*>>?\|?)\s*\/dev\/\S*/g, " "); // > /dev/null, 2>/dev/null, &> /dev/null
  return /(?<![=-])>/.test(cleaned);
}

function segmentWrites(words: string[]): boolean {
  let i = 0;
  while (i < words.length && (/^\w+=/.test(words[i] ?? "") || WRAPPERS.has(words[i] ?? "") || KEYWORDS.has(words[i] ?? ""))) i++;
  const cmd = (words[i] ?? "").replace(/^.*\//, "");
  const args = words.slice(i + 1);
  if (WRITE_COMMANDS.has(cmd)) return true;
  if (cmd === "sed") return args.some((a) => a === "--in-place" || a.startsWith("--in-place=") || /^-[a-zA-Z]*i/.test(a));
  if (cmd === "perl") return args.some((a) => /^-[a-zA-Z]*i/.test(a));
  if (cmd === "git") return GIT_WRITE_SUBCOMMANDS.has(gitSubcommand(args));
  return false;
}

// gitSubcommand is the first non-option word, skipping the value of the global
// options that take one (git -C dir apply).
function gitSubcommand(args: string[]): string {
  for (let k = 0; k < args.length; k++) {
    const a = args[k] ?? "";
    if (GIT_VALUE_OPTIONS.has(a)) k++;
    else if (!a.startsWith("-")) return a;
  }
  return "";
}
