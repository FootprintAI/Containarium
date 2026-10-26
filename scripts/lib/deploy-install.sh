#!/usr/bin/env bash
# Remote install step shared by scripts/deploy-binary.sh and its test (#3060).
#
# deploy_install_cmd <service> [health-url] prints one shell command for the
# target host. It stops the unit, keeps the binary it is replacing as
# <bin>.old, installs the new one, starts the unit and checks health. If the
# unit does not become healthy it puts <bin>.old back, starts the unit again
# and exits non-zero, so the caller's ssh (and `set -e`) stops the rollout.
#
# Health is `curl -f <health-url>` when a URL is given, otherwise the unit
# being active. Knobs, read when the command is built: BIN_DIR (default
# /usr/local/bin), SRC (default /tmp/containariumd), HEALTH_TRIES (default 15),
# HEALTH_INTERVAL seconds (default 2).
deploy_install_cmd() {
    local svc="$1" url="${2:-}"
    local dir="${BIN_DIR:-/usr/local/bin}" src="${SRC:-/tmp/containariumd}"
    local tries="${HEALTH_TRIES:-15}" interval="${HEALTH_INTERVAL:-2}"
    local bin="$dir/containariumd" check
    if [ -n "$url" ]; then
        check="curl -fsS --max-time 3 '$url' >/dev/null 2>&1"
    else
        check="sudo systemctl is-active --quiet '$svc'"
    fi
    cat <<CMD
had_old=0
sudo systemctl stop '$svc' && sleep 1 || exit 1
if [ -f '$bin' ]; then sudo cp -p '$bin' '$bin.old' && had_old=1 || exit 1; fi
sudo cp '$src' '$bin' && sudo chmod +x '$bin' || exit 1
if [ '$dir' = /usr/local/bin ]; then sudo ln -sf '$bin' '$dir/containarium'; fi
sudo systemctl start '$svc'
i=0
while [ \$i -lt $tries ]; do
  if $check; then echo "  $svc healthy after install"; exit 0; fi
  i=\$((i+1)); sleep $interval
done
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
