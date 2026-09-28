# shellcheck shell=sh
#
# /etc/profile.d/containarium-tmux.sh: installed into every box by the
# Containarium daemon (see pkg/core/container/tmux_login_hook.go, #2121).
#
# A genuine interactive login (plain `ssh box`, or a mosh session) lands in a
# persistent tmux session named "main", so a dropped mobile link costs
# nothing: the next login re-attaches to the same session.
#
# It must stay out of the way of everything else, so it starts tmux only when
# EVERY guard below holds. Each guard exists for a concrete caller:
#   interactive shell ($- has i)  ssh host <cmd>, scp/sftp/rsync, code run,
#                                 connect --exec, agent-box/MCP stdio sessions
#                                 (on RHEL /etc/bashrc sources profile.d even
#                                 for those, so this is load-bearing there)
#   login shell ($0 is "-...")    ssh -t host <cmd> / ssh -t host bash: sshd
#                                 only starts a login shell when there is no
#                                 command; a shell the user runs by hand is not
#   stdin+stdout are a tty        no pty, nothing to attach tmux to
#   SSH_TTY set, or the parent    IDE remote terminals (VS Code, JetBrains):
#   is mosh-server                they inherit SSH_CONNECTION from the IDE
#                                 server's non-pty ssh session but not SSH_TTY.
#                                 A real mosh login (checked with mosh 1.4.0)
#                                 keeps a stale SSH_TTY from the ssh session
#                                 that launched mosh-server, so it passes via
#                                 the SSH_TTY branch; the mosh-server parent
#                                 check is only a harmless fallback, for a
#                                 mosh whose login shell has no SSH_TTY
#   TMUX unset / STY unset        already inside tmux (this includes
#                                 `containarium connect --session`) or screen
#   TERM_PROGRAM != vscode,       belt and braces for IDE terminals
#   TERMINAL_EMULATOR != JetBrains*
#   CONTAINARIUM_NO_TMUX != 1,    the user's opt-out
#   no ~/.containarium/no-tmux
#   tmux on PATH and `tmux -V` runs
#
# Fail open: tmux is NOT exec'd. If it exits non-zero (it failed to start,
# e.g. an unusable TERM) the login shell carries on as a normal shell. Only a
# clean tmux exit (detach, or the last window closed) ends the login.
#
# POSIX sh: /etc/profile sources this under whatever login shell the user has.

containarium_tmux_should_start() {
	case $- in *i*) ;; *) return 1 ;; esac
	case $0 in -*) ;; *) return 1 ;; esac
	[ -t 0 ] && [ -t 1 ] || return 1
	[ -z "${TMUX:-}" ] || return 1
	[ -z "${STY:-}" ] || return 1
	[ "${TERM_PROGRAM:-}" != vscode ] || return 1
	case ${TERMINAL_EMULATOR:-} in JetBrains*) return 1 ;; esac
	[ "${CONTAINARIUM_NO_TMUX:-}" != 1 ] || return 1
	[ ! -e "${HOME:-/nonexistent}/.containarium/no-tmux" ] || return 1
	if [ -z "${SSH_TTY:-}" ]; then
		[ "$(cat "/proc/${PPID:-0}/comm" 2>/dev/null)" = mosh-server ] || return 1
	fi
	command -v tmux >/dev/null 2>&1 || return 1
	tmux -V >/dev/null 2>&1 || return 1
	return 0
}

if containarium_tmux_should_start; then
	unset -f containarium_tmux_should_start
	if tmux new -A -s main; then
		exit 0
	fi
	echo "containarium: tmux did not start; continuing with a plain shell (opt out: touch ~/.containarium/no-tmux)" >&2
else
	unset -f containarium_tmux_should_start
fi
