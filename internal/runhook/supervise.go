//go:build !windows

package runhook

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// SuperviseUsage is the run-supervise usage line. The daemon's setup checks
// the box's agent-box prints it, so an agent-box without the supervisor is
// refused rather than trusted.
const SuperviseUsage = "usage: agent-box run-supervise --config <path> --user <name> --dir <dir> --command <script>"

// supervisePath is the PATH of the run's login environment, as `su -` gives.
const supervisePath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// superviseSpec is one supervised run.
type superviseSpec struct {
	// Shell runs Command as a login shell ("-<shell> -c <command>"), the way
	// `su - <user> -c` does.
	Shell   string
	Command string
	Dir     string
	Env     []string
	// Cred is the run user; nil keeps the caller's identity (tests).
	Cred *syscall.Credential
	// ExitPath receives "<status> <epoch>" once the run has ended.
	ExitPath string
}

// supervise starts the run as its own session (so its process group is the
// run user's alone, as StopBoxRun expects), writes "<pid> <boot_id>" to
// launch, waits for it, and records its exit status, as the run's parent, at
// spec.ExitPath: the exit code, 128+signal for a signalled run. Only this
// process (root, outside the run's session) writes that file, so nothing in
// the run can choose the status the sink reads.
func supervise(spec superviseSpec, launch io.Writer) error {
	cmd := exec.Command(spec.Shell, "-c", spec.Command)
	cmd.Args[0] = "-" + filepath.Base(spec.Shell)
	cmd.Dir = spec.Dir
	cmd.Env = spec.Env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Credential: spec.Cred}
	if err := cmd.Start(); err != nil {
		return err
	}
	boot, _ := os.ReadFile("/proc/sys/kernel/random/boot_id")
	// If this write fails the launch script refuses the run; the run itself
	// still gets its status recorded below.
	_, _ = fmt.Fprintf(launch, "%d %s\n", cmd.Process.Pid, strings.TrimSpace(string(boot)))
	err := cmd.Wait()
	code := 0
	var ee *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &ee):
		code = ee.ExitCode()
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			code = 128 + int(ws.Signal())
		}
	default:
		code = 1
	}
	return writeExitStatus(spec.ExitPath, code, time.Now())
}

// writeExitStatus atomically writes "<code> <epoch>" to path (0600).
func writeExitStatus(path string, code int, now time.Time) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(fmt.Sprintf("%d %d", code, now.Unix())), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// passwdEntry is the part of a passwd line the supervisor needs.
type passwdEntry struct {
	uid, gid    uint32
	home, shell string
}

// lookupPasswd reads name's entry from a passwd file.
func lookupPasswd(path, name string) (passwdEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return passwdEntry{}, err
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		p := strings.Split(sc.Text(), ":")
		if len(p) < 7 || p[0] != name {
			continue
		}
		uid, err1 := strconv.ParseUint(p[2], 10, 32)
		gid, err2 := strconv.ParseUint(p[3], 10, 32)
		if err1 != nil || err2 != nil {
			return passwdEntry{}, fmt.Errorf("%s: malformed entry for %q", path, name)
		}
		return passwdEntry{uid: uint32(uid), gid: uint32(gid), home: p[5], shell: p[6]}, nil
	}
	if err := sc.Err(); err != nil {
		return passwdEntry{}, err
	}
	return passwdEntry{}, fmt.Errorf("no user %q", name)
}

// RunSuperviseCLI is `agent-box run-supervise --config <path> --user <name>
// --dir <dir> --command <script>`, started detached, as root, by the daemon
// in place of spawning the run as the run user. It runs the script as that
// user (a login shell in its own session, as `su - <user> -c` would), prints
// the run's "<pid> <boot_id>" on stdout, and writes the run's exit status to
// the configuration's root-owned ExitPath once the run ends.
func RunSuperviseCLI(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("run-supervise", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("config", "", "the run's configuration")
	name := fs.String("user", "", "the run user")
	dir := fs.String("dir", "", "the run's working directory")
	command := fs.String("command", "", "the run's shell script")
	if err := fs.Parse(args); err != nil || *path == "" || *name == "" || *dir == "" || *command == "" {
		fmt.Fprintln(stderr, SuperviseUsage)
		return 2
	}
	cfg, err := LoadConfig(*path)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if cfg.ExitPath == "" {
		fmt.Fprintln(stderr, "the run's configuration has no exit_path")
		return 1
	}
	pw, err := lookupPasswd("/etc/passwd", *name)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if pw.uid == 0 {
		fmt.Fprintln(stderr, "refusing to supervise a run as root")
		return 1
	}
	var groups []uint32
	if u, err := user.Lookup(*name); err == nil {
		if ids, err := u.GroupIds(); err == nil {
			for _, id := range ids {
				if g, err := strconv.ParseUint(id, 10, 32); err == nil {
					groups = append(groups, uint32(g))
				}
			}
		}
	}
	shell := pw.shell
	if shell == "" || !filepath.IsAbs(shell) {
		shell = "/bin/sh"
	}
	spec := superviseSpec{
		Shell:   shell,
		Command: *command,
		Dir:     *dir,
		Env: []string{
			"HOME=" + pw.home, "USER=" + *name, "LOGNAME=" + *name,
			"SHELL=" + shell, "PATH=" + supervisePath,
		},
		Cred:     &syscall.Credential{Uid: pw.uid, Gid: pw.gid, Groups: groups},
		ExitPath: cfg.ExitPath,
	}
	if err := supervise(spec, stdout); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}
