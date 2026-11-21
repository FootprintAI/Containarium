#!/bin/bash
# Tests for the containarium-zfs-backup script embedded in
# scripts/setup-gpu-host.sh (#3595): per-dataset replication, self-healing of a
# wedged backup pool, and a non-zero exit when replication fails.
#
# Real ZFS needs root and a pool, so this extracts the real script from the
# heredoc and runs it against a fake `zfs`/`zpool`/`date` that model datasets
# and snapshots in plain files and enforce the receive rules that caused the
# bug (incremental into a missing dataset fails; full stream into a dataset that
# already has snapshots fails).
set -uo pipefail

FILE="$(cd "$(dirname "$0")" && pwd)/setup-gpu-host.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
fail=0
ok()  { echo "PASS: $1"; }
bad() { echo "FAIL: $1"; fail=1; }

sed -n "/<<'BACKUPEOF'/,/^BACKUPEOF/p" "$FILE" | sed '1d;$d' > "$tmp/backup.sh"
[ -s "$tmp/backup.sh" ] || { echo "FAIL: backup script not found in setup-gpu-host.sh"; exit 1; }

bin="$tmp/bin"; mkdir -p "$bin"
export FAKE="$tmp/state"; mkdir -p "$FAKE"
export PATH="$bin:$PATH"
export CONTAINARIUM_BACKUP_STATUS_FILE="$tmp/status/zfs-backup.status"

cat > "$bin/date" <<'DEOF'
#!/bin/bash
n=$(( $(cat "$FAKE/clock" 2>/dev/null || echo 0) + 1 )); echo "$n" > "$FAKE/clock"
case "$1" in +%s) echo "$((1700000000 + n))";; *) printf '20260101-%06d\n' "$n";; esac
DEOF

cat > "$bin/zpool" <<'ZEOF'
#!/bin/bash
# zpool list [-H -o capacity] POOL
pool="${@: -1}"
grep -qx "$pool" "$FAKE/pools" || exit 1
case " $* " in *capacity*) cat "$FAKE/cap" 2>/dev/null || echo "10%";; esac
ZEOF

cat > "$bin/zfs" <<'ZEOF'
#!/bin/bash
D="$FAKE/datasets"; S="$FAKE/snaps"; touch "$D" "$S"
cmd="$1"; shift
under() { awk -v p="$1" '$0==p || index($0, p"/")==1' ; }
case "$cmd" in
snapshot)  # snapshot -r POOL@SNAP
    t="${@: -1}"; pool="${t%@*}"; snap="${t#*@}"
    under "$pool" < "$D" | while read -r d; do echo "$d@$snap" >> "$S"; done ;;
list)
    typ=""; rec=0; target=""
    while [ $# -gt 0 ]; do case "$1" in
        -t) typ="$2"; shift 2;; -r) rec=1; shift;; -o|-S) shift 2;; -H) shift;; *) target="$1"; shift;; esac; done
    if [ "$typ" = snapshot ]; then
        if [ "$rec" = 1 ]; then tac "$S" | awk -v p="$target" '{d=$0; sub(/@.*/,"",d)} d==p || index(d,p"/")==1'
        else tac "$S" | awk -v p="$target" '{d=$0; sub(/@.*/,"",d)} d==p'; fi
    elif [[ "$target" == *@* ]]; then grep -qx "$target" "$S"
    elif [ "$rec" = 1 ]; then under "$target" < "$D"
    else grep -qx "$target" "$D"; fi ;;
destroy)
    rec=0; [ "$1" = -r ] && { rec=1; shift; }; t="$1"
    if [[ "$t" == *@* ]]; then grep -vx "$t" "$S" > "$S.n"; mv "$S.n" "$S"
    else
        [ "$rec" = 0 ] && grep -q "^$t@" "$S" && { echo "cannot destroy '$t': dataset has snapshots" >&2; exit 1; }
        under "$t" < "$D" > "$S.del"
        grep -vxFf "$S.del" "$D" > "$D.n"; mv "$D.n" "$D"
        awk 'NR==FNR{del[$0]=1;next} {d=$0; sub(/@.*/,"",d)} !(d in del)' "$S.del" "$S" > "$S.n"; mv "$S.n" "$S"
    fi ;;
send)  # send [-p] [-i @from] ds@snap
    from="-"; while [ $# -gt 1 ]; do case "$1" in -i) from="${2#@}"; shift 2;; *) shift;; esac; done
    t="$1"; grep -qx "$t" "$S" || { echo "cannot open '$t'" >&2; exit 1; }
    echo "STREAM ${t%@*} ${t#*@} $from" ;;
receive)
    dest="${@: -1}"; read -r _ ds snap from || { echo "empty stream" >&2; exit 1; }
    [ -e "$FAKE/receive_fail" ] && { echo "cannot receive: out of space (quota)" >&2; exit 1; }
    if [ "$from" = "-" ]; then
        if grep -q "^$dest@" "$S"; then echo "cannot receive new filesystem stream: destination has snapshots" >&2; exit 1; fi
        grep -qx "${dest%/*}" "$D" || { echo "cannot receive: parent does not exist" >&2; exit 1; }
        grep -qx "$dest" "$D" || echo "$dest" >> "$D"
    else
        grep -qx "$dest" "$D" || { echo "cannot receive incremental stream: destination '$dest' does not exist" >&2; exit 1; }
        grep -qx "$dest@$from" "$S" || { echo "cannot receive incremental stream: most recent snapshot does not match" >&2; exit 1; }
    fi
    echo "$dest@$snap" >> "$S" ;;
*) echo "fake zfs: unsupported $cmd" >&2; exit 2 ;;
esac
ZEOF
chmod +x "$bin"/*

BK=incus-backup/snapshots/incus-local

reset() {
    rm -rf "$FAKE" "$tmp/status"; mkdir -p "$FAKE"
    printf '%s\n' incus-local incus-backup > "$FAKE/pools"
    printf '%s\n' incus-local incus-local/containers incus-local/containers/alpha \
        incus-backup incus-backup/snapshots > "$FAKE/datasets"
}
run() { bash "$tmp/backup.sh" "$@" > "$tmp/out" 2>&1; rc=$?; }
has() { grep -qx "$1" "$FAKE/datasets"; }
status() { sed -n "s/^$1=//p" "$CONTAINARIUM_BACKUP_STATUS_FILE"; }

# 1. First run: full replication of every dataset, exit 0.
reset; run
if [ "$rc" = 0 ] && has "$BK/containers/alpha" && [ "$(status status)" = ok ]; then
    ok "first run replicates the whole tree and exits 0"
else bad "first run (rc=$rc)"; cat "$tmp/out"; fi

# 2. A child created after the last good run is replicated (the #3595 wedge).
echo incus-local/containers/beta >> "$FAKE/datasets"
run
if [ "$rc" = 0 ] && has "$BK/containers/beta" && grep -q "^$BK/containers/beta@backup-" "$FAKE/snaps"; then
    ok "child created after the first run is replicated; exit 0"
else bad "new child not replicated (rc=$rc)"; cat "$tmp/out"; fi

# 3. A forced receive failure exits non-zero, names the dataset, still prunes.
touch "$FAKE/receive_fail"
echo incus-local/containers/gamma >> "$FAKE/datasets"
run
if [ "$rc" != 0 ] && [ "$(status status)" = failed ] && [[ "$(status failed_datasets)" == *gamma* ]] \
   && grep -q "Pruning old snapshots" "$tmp/out"; then
    ok "forced receive failure exits non-zero, writes status, still prunes"
else bad "receive failure not loud (rc=$rc)"; cat "$tmp/out"; fi

# 4. Recovery with no manual zfs destroy once the condition is fixed.
rm "$FAKE/receive_fail"
run
if [ "$rc" = 0 ] && has "$BK/containers/gamma" && [ "$(status status)" = ok ]; then
    ok "next run after the fault is fixed recovers on its own"
else bad "no recovery (rc=$rc)"; cat "$tmp/out"; fi

# 5. A diverged replica (has snapshots, none shared with the source) is repaired.
grep -v "^$BK/containers/alpha@" "$FAKE/snaps" > "$FAKE/snaps.n"; mv "$FAKE/snaps.n" "$FAKE/snaps"
echo "$BK/containers/alpha@backup-stale" >> "$FAKE/snaps"
run
if [ "$rc" = 0 ] && ! grep -qx "$BK/containers/alpha@backup-stale" "$FAKE/snaps" \
   && grep -q "^$BK/containers/alpha@backup-" "$FAKE/snaps"; then
    ok "diverged replica is destroyed and re-sent"
else bad "diverged replica not repaired (rc=$rc)"; cat "$tmp/out"; fi

# 6. Pool-full warning.
echo "93%" > "$FAKE/cap"; run
if grep -q "WARNING: pool incus-local is 93% full" "$tmp/out"; then ok "warns when the live pool is above threshold"
else bad "no capacity warning"; cat "$tmp/out"; fi
rm "$FAKE/cap"

# 7. --prune keeps the default of 7 per dataset and is unchanged.
reset
for i in 1 2 3 4 5 6 7 8 9; do echo "incus-local@backup-$i" >> "$FAKE/snaps"; done
run --prune
n=$(grep -c '^incus-local@backup-' "$FAKE/snaps")
if [ "$rc" = 0 ] && [ "$n" = 7 ] && grep -qx 'incus-local@backup-9' "$FAKE/snaps" && ! grep -qx 'incus-local@backup-1' "$FAKE/snaps"; then
    ok "--prune keeps the newest 7 per dataset"
else bad "--prune changed (kept $n)"; fi

# 8. The pipefail comment matches reality.
if grep -q 'pipefail is intentionally NOT set' "$tmp/backup.sh"; then bad "stale pipefail comment"; else ok "pipefail comment fixed"; fi

exit "$fail"
