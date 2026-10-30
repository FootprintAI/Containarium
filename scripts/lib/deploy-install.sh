#!/usr/bin/env bash
# Remote install step shared by scripts/deploy-binary.sh and its test (#3060).
#
# deploy_install_cmd <service> [health-url] prints one shell command for the
# target host. It stops the unit, keeps the binary it is replacing as
# <bin>.old, installs the new one, starts the unit and checks health. If the
# unit does not become healthy it puts <bin>.old back, starts the unit again
# and exits non-zero, so the caller's ssh (and `set -e`) stops the rollout.
#
# Health is `curl -f <health-url>` when a URL is given: the first success
# within the window passes. Without a URL (the sentinel) health is the unit
# staying active, in the same systemd invocation (InvocationID unchanged), for
# the whole window, so a binary that is active right after
# `systemctl start` and crashes a moment later still rolls back (#3108).
#
# Knobs, read when the command is built: BIN_DIR (default /usr/local/bin),
# SRC (default /tmp/containariumd), HEALTH_TRIES (default 15), HEALTH_INTERVAL
# seconds (default 2). The window is HEALTH_TRIES x HEALTH_INTERVAL, 30s by
# default. Both must be plain decimal integers, no sign and no leading zeros
# (a bare 0 is valid for HEALTH_INTERVAL): HEALTH_TRIES 1 to 9999,
# HEALTH_INTERVAL 0 to 9999. Anything else, including an empty value, is
# rejected; scripts/deploy-binary.sh checks this before its first remote call,
# and deploy_install_cmd checks again before it builds the command.
# A successful sentinel deploy always takes the full window. A daemon that is
# healthy but needs longer than the window to come up (URL path) or to settle
# is rolled back like a broken one: raise HEALTH_TRIES
# (or HEALTH_INTERVAL) for a slow-starting daemon, e.g.
#   HEALTH_TRIES=60 HEALTH_INTERVAL=2 scripts/deploy-binary.sh ...
#
# deploy_validate_knobs <tries> <interval> prints the problem(s) on one line
# and returns 1 when a knob is unusable; prints nothing and returns 0 otherwise.
# HEALTH_TRIES is 1..9999, HEALTH_INTERVAL is 0..9999 seconds: plain decimal
# integers, no sign, no leading zeros (a bare 0 is valid for the interval only),
# at most 4 digits. Values are quoted with %q so a control character in the
# value never reaches the terminal. The check runs under LC_ALL=C, so digits of
# other scripts never match. scripts/deploy-binary.sh calls this before
# its first remote call; deploy_install_cmd calls it again.
deploy_validate_knobs() {
    local LC_ALL=C tries="$1" interval="$2" err="" q
    case "$tries" in
        [1-9]|[1-9][0-9]|[1-9][0-9][0-9]|[1-9][0-9][0-9][0-9]) ;;
        *) printf -v q '%q' "$tries"
           err="HEALTH_TRIES must be an integer from 1 to 9999 without leading zeros, got $q";;
    esac
    case "$interval" in
        0|[1-9]|[1-9][0-9]|[1-9][0-9][0-9]|[1-9][0-9][0-9][0-9]) ;;
        *) printf -v q '%q' "$interval"
           err="${err:+$err; }HEALTH_INTERVAL must be an integer from 0 to 9999 (seconds) without leading zeros, got $q";;
    esac
    [ -z "$err" ] || { printf '%s' "$err"; return 1; }
}

# The service name and URL are placed inside single quotes in the generated
# command. They come from operator env (SENTINEL_SERVICE, PRIMARY_SERVICE,
# *_HEALTH_URL), never from untrusted input, and must not contain a `'`.
deploy_install_cmd() {
    local svc="$1" url="${2:-}"
    local dir="${BIN_DIR:-/usr/local/bin}" src="${SRC:-/tmp/containariumd}"
    local tries="${HEALTH_TRIES-15}" interval="${HEALTH_INTERVAL-2}"
    local bin="$dir/containariumd" check poll final inv_get inv_same inv_init=":"
    # A rollback gate must not pass vacuously: reject bad knobs before any
    # change to the host. The emitted command fails too, because callers
    # embed this output in `--command="$(...)"`, where a non-zero return of
    # this function alone would not stop the deploy.
    local knob_err
    if ! knob_err="$(deploy_validate_knobs "$tries" "$interval")"; then
        echo "ERROR: $knob_err" >&2
        printf 'echo %q >&2; exit 1\n' "ERROR: $knob_err"
        return 1
    fi
    if [ -n "$url" ]; then
        check="curl -fsS --max-time 3 '$url' >/dev/null 2>&1"
        # Healthy on the first successful probe.
        poll="if $check; then echo \"  $svc healthy after install\"; exit 0; fi"
        final="false"
    else
        # A restart always gets a new InvocationID. Comparing it with the one
        # recorded after start catches a crash and systemd restart that fell
        # between two probes, which is-active alone cannot see. It cannot
        # catch a restart that lands between `systemctl start` returning and
        # the id being recorded: the recorded id is then already the new one.
        # If the id is unreadable at record time the check degrades to
        # is-active alone; one lost later, after it was recorded, fails the
        # check.
        inv_get="sudo systemctl show -p InvocationID --value '$svc' 2>/dev/null"
        inv_init="inv=\$($inv_get)"
        inv_same="[ \"\$($inv_get)\" = \"\$inv\" ]"
        check="sudo systemctl is-active --quiet '$svc' && $inv_same"
        # Healthy only if still active, and the same invocation, after the
        # whole window: a failed probe ends the wait at once and falls
        # through to the rollback.
        poll="if ! { $check; }; then break; fi"
        # The last probe is followed by a sleep; probe once more after it so
        # the whole window is watched.
        final="{ $check; }"
    fi
    cat <<CMD
had_old=0
sudo systemctl stop '$svc' && sleep 1 || exit 1
if [ -f '$bin' ]; then sudo cp -p '$bin' '$bin.old' && had_old=1 || exit 1; fi
sudo cp '$src' '$bin' && sudo chmod +x '$bin' || exit 1
if [ '$dir' = /usr/local/bin ]; then sudo ln -sf '$bin' '$dir/containarium'; fi
sudo systemctl start '$svc'
$inv_init
i=0
while [ \$i -lt $tries ]; do
  $poll
  i=\$((i+1)); sleep $interval
done
if [ -z '$url' ] && [ \$i -ge $tries ] && $final; then echo "  $svc healthy after install"; exit 0; fi
echo "  ERROR: $svc not healthy after install" >&2
if [ \$had_old = 1 ]; then
  sudo systemctl stop '$svc' || true
  if sudo mv '$bin.old' '$bin' && sudo systemctl start '$svc'; then
    echo "  rolled back to the previous binary ($bin)" >&2
  else
    echo "  ROLLBACK FAILED: could not restore and restart the previous binary; $svc needs manual recovery ($bin.old)" >&2
  fi
else
  echo "  no previous binary to restore; $svc left as is" >&2
fi
exit 1
CMD
}
