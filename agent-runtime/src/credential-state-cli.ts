// Private metadata-only protocol. Linux flock releases the lock on process death.
import {
  closeSync,
  constants,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { randomUUID } from "node:crypto";
import { homedir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
export interface Episode {
  id: string;
  afterRecovery: boolean;
}
interface State {
  version: 1;
  next: number;
  lastFailure: number;
  lastSuccess: number;
  lateEpisode: string | null;
  recovered: boolean;
  active: string | null;
  pending: Episode[];
}
export interface Observation {
  version: 1;
  active: boolean;
  pending: Episode[];
}
export function stateCommand(home: string, args: string[]): unknown {
  const result = spawnSync(
    process.execPath,
    [
      fileURLToPath(
        new URL("../dist/credential-state-cli.js", import.meta.url),
      ),
      ...args,
    ],
    {
      env: { HOME: home, PATH: process.env.PATH ?? "/usr/bin:/bin" },
      encoding: "utf8",
      maxBuffer: 1 << 20,
      timeout: 15000,
    },
  );
  if (result.error || result.status !== 0)
    throw new Error("credential state unavailable");
  return JSON.parse(result.stdout) as unknown;
}
function locked(home: string, args: string[]): unknown {
  const dir = join(home, ".local", "state", "containarium"),
    path = join(dir, "claude-auth-state.json");
  let state: State = {
    version: 1,
    next: 0,
    lastFailure: 0,
    lastSuccess: 0,
    lateEpisode: null,
    recovered: false,
    active: null,
    pending: [],
  };
  if (existsSync(path)) {
    const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      state = JSON.parse(readFileSync(fd, "utf8")) as State;
    } finally {
      closeSync(fd);
    }
    state.lastSuccess ??= 0;
    state.lateEpisode ??= null;
    if (
      state.version !== 1 ||
      !Number.isSafeInteger(state.next) ||
      !Array.isArray(state.pending) ||
      state.next < 0 ||
      !Number.isSafeInteger(state.lastFailure) ||
      state.lastFailure < 0 ||
      state.lastFailure > state.next ||
      !Number.isSafeInteger(state.lastSuccess) ||
      state.lastSuccess < 0 ||
      state.lastSuccess > state.next ||
      typeof state.recovered !== "boolean" ||
      (state.active !== null && !/^[a-f0-9-]{36}$/.test(state.active)) ||
      (state.lateEpisode !== null &&
        !/^[a-f0-9-]{36}$/.test(state.lateEpisode)) ||
      state.pending.some(
        (e) =>
          typeof e.afterRecovery !== "boolean" || !/^[a-f0-9-]{36}$/.test(e.id),
      )
    )
      throw new Error("invalid state");
  }
  const [verb, ...params] = args;
  if (verb === "snapshot")
    return {
      version: 1,
      active: state.active !== null,
      pending: state.pending.slice(0, 256),
    };
  let output: unknown = {};
  if (verb === "begin") {
    if (!Number.isSafeInteger(++state.next))
      throw new Error("generation exhausted");
    output = { generation: state.next };
  } else if (verb === "finish") {
    const [raw, source, outcome] = params,
      generation = Number(raw);
    if (
      !Number.isSafeInteger(generation) ||
      generation <= 0 ||
      generation > state.next ||
      !["oauth", "key", "unknown"].includes(source) ||
      !["success", "failure", "other"].includes(outcome)
    )
      throw new Error("invalid outcome");
    if (source === "oauth" && outcome === "failure") {
      if (generation < state.lastSuccess) {
        // A newer run already proved recovery. Preserve this late failure's
        // evidence, but don't invalidate the newer authenticated session.
        if (state.lateEpisode === null) {
          state.lateEpisode = randomUUID();
          state.pending.push({ id: state.lateEpisode, afterRecovery: false });
        }
      } else {
        if (state.active === null) {
          state.active = randomUUID();
          state.pending.push({
            id: state.active,
            afterRecovery: state.recovered,
          });
        }
        state.recovered = false;
      }
      state.lastFailure = Math.max(state.lastFailure, generation);
    } else if (
      source === "oauth" &&
      outcome === "success" &&
      generation > state.lastFailure &&
      generation > state.lastSuccess
    ) {
      state.lastSuccess = generation;
      state.lateEpisode = state.active;
      state.active = null;
      state.recovered = true;
    }
  } else if (verb === "ack") {
    if (params.length > 256 || params.some((id) => !/^[a-f0-9-]{36}$/.test(id)))
      throw new Error("invalid acknowledgement");
    const ids = new Set(params);
    state.pending = state.pending.filter((e) => !ids.has(e.id));
  } else throw new Error("invalid command");
  const temp = join(dir, `.auth-state-${randomUUID()}`);
  try {
    const fd = openSync(temp, "wx", 0o600);
    try {
      writeFileSync(fd, JSON.stringify(state));
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    renameSync(temp, path);
    const fdDir = openSync(dir, "r");
    try {
      fsyncSync(fdDir);
    } finally {
      closeSync(fdDir);
    }
  } finally {
    rmSync(temp, { force: true });
  }
  return output;
}
function isEntry(): boolean {
  try {
    return (
      Boolean(process.argv[1]) &&
      realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)
    );
  } catch {
    return false;
  }
}
if (isEntry()) {
  try {
    const home = homedir(),
      dir = join(home, ".local", "state", "containarium");
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const args = process.argv.slice(2);
    if (args[0] === "--locked")
      process.stdout.write(JSON.stringify(locked(home, args.slice(1))) + "\n");
    else {
      const lock = join(dir, "claude-auth.lock");
      closeSync(openSync(lock, "a", 0o600));
      const result = spawnSync(
        "flock",
        [
          "-x",
          "-w",
          "5",
          lock,
          process.execPath,
          fileURLToPath(import.meta.url),
          "--locked",
          ...args,
        ],
        { stdio: "inherit" },
      );
      process.exitCode = result.status ?? 1;
    }
  } catch {
    process.stderr.write("credential state unavailable\n");
    process.exitCode = 1;
  }
}
