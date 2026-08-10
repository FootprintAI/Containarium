# shellcheck shell=sh
#
# Build the session environment from the box's mounted secrets (#1190).
#
# The daemon materializes a tenant's secrets into a Kubernetes Secret mounted
# at /run/secrets, one file per secret. This turns those files into
# environment variables, so an env-delivery secret behaves the same as it does
# on the LXC backend, where it arrives via `incus config set environment.<NAME>`.
#
# Sourced per session rather than once at container start, and that is the
# point: the kubelet refreshes the mount in place when the Secret changes, so
# a new session sees the current value without the box restarting. That is
# also exactly what the LXC path promises — "new execs will see updated
# values" — so the two backends agree.

containarium_load_secrets() {
	[ -d /run/secrets ] || return 0

	for _cs_file in /run/secrets/*; do
		# An unmatched glob stays literal, so check the file exists. The
		# check follows symlinks, which matters: Kubernetes projects each
		# key as a symlink into a ..data directory.
		[ -f "$_cs_file" ] || continue

		_cs_name=${_cs_file##*/}

		# Only names that are valid shell identifiers. A secret named
		# `foo-bar` would fail the export, and one bad name must not stop
		# the rest loading.
		#
		# This also covers the compose dotenv: `secrets.env` contains a dot,
		# so it is never a valid identifier and is never exported. It is
		# consumed as a file by `env_file:`, and exporting it would make one
		# variable whose value is the whole file. An explicit *.env case
		# here would be unreachable — the check below already refuses it.
		case "$_cs_name" in
		[!A-Za-z_]* | *[!A-Za-z0-9_]*) continue ;;
		esac

		# PATH, LD_PRELOAD and friends are refused: a tenant secret must not
		# be able to redirect what the session executes.
		case "$_cs_name" in
		PATH | LD_* | IFS | ENV | BASH_ENV | SHELL | HOME) continue ;;
		esac

		# Command substitution strips trailing newlines, which is what a
		# consumer of an env var expects — the file has one, the variable
		# should not.
		_cs_value=$(cat "$_cs_file") || continue
		export "$_cs_name=$_cs_value"
	done

	unset _cs_file _cs_name _cs_value
}

containarium_load_secrets
