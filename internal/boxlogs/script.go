package boxlogs

import (
	"fmt"
	"strings"
)

// ScriptParams is everything the collection script is parameterized by.
// Only integers, a validated journal cursor and validated unit names reach
// the script text; Script re-checks each one, so a value that slipped past
// Prepare is dropped rather than quoted into the script.
type ScriptParams struct {
	// Root prefixes the paths the runtime probe looks at (proc/, run/,
	// var/run/). Empty in production; tests point it at a fake box.
	Root           string
	ReadJournal    bool
	ReadContainers bool
	// JournalCursor resumes the journal after (or, with JournalInclusive,
	// at) this entry.
	JournalCursor    string
	JournalInclusive bool
	// JournalSince is a unix time in seconds; 0 means none.
	JournalSince int64
	// ContainerSince is a unix time in nanoseconds; 0 means none.
	ContainerSince int64
	// Tail reads only the last Tail lines of each source; 0 reads forward.
	Tail int
	// Lines caps the lines read from each source.
	Lines int
	Units []string
	// Budget is how many seconds the readers may run in all.
	Budget int
}

// scriptBody is the fixed collector. It reads its parameters from the
// shell variables Script assigns above it and prints the frames Parse reads.
// Container ids and names come from `docker ps`: an id is used only after it
// is checked to be 64 hex digits, and a name is only ever printed.
const scriptBody = `set -u
export LC_ALL=C
left() {
  r=$(( end - $(date +%s) ))
  [ "$r" -gt 0 ] || r=0
  echo "$r"
}
# run_source LINES CUT PREFIX MERGE_STDERR CMD...: run a reader under the
# remaining budget, keep its first LINES lines cut to CUT bytes behind
# PREFIX (on fd 3), and print the reader's exit code.
run_source() {
  lim=$1; cb=$2; pre=$3; merge=$4; shift 4
  r=$(left)
  if [ "$r" -le 0 ]; then echo 124; return; fi
  if [ "$merge" = 1 ]; then
    { { timeout -k 1 "$r" "$@" 2>&1; echo "$?" >&4; } | head -n "$lim" | cut -b "1-$cb" | sed "s/^/$pre /" >&3; } 4>&1
  else
    { { timeout -k 1 "$r" "$@" 2>/dev/null; echo "$?" >&4; } | head -n "$lim" | cut -b "1-$cb" | sed "s/^/$pre /" >&3; } 4>&1
  fi
}
collect() {
  exec 3>&1
  echo "V 1"
  echo "N $(date +%s%N)"
  rt=none
  if grep -qsx conmon "$root"/proc/[0-9]*/comm 2>/dev/null; then
    rt=podman
  else
    for s in "$root"/run/user/*/docker.sock; do
      if [ -S "$s" ]; then rt=docker-rootless; fi
    done
    if [ "$rt" = none ] && [ -S "$root/var/run/docker.sock" ] && command -v docker >/dev/null 2>&1; then
      case "$(timeout -k 1 2 docker --version 2>/dev/null)" in
        *[Pp]odman*) rt=podman ;;
        *) rt=docker ;;
      esac
    fi
  fi
  echo "R $rt"
  case "$rt" in docker|none) ;; *) return 0 ;; esac
  set -f
  timeout -k 1 2 systemctl list-units --all --type=service --no-legend --plain --no-pager 2>/dev/null | head -n 512 |
    while read -r u _; do printf 'U %s\n' "$u"; done
  n=0
  ids=
  if [ "$rt" = docker ]; then
    list=$(timeout -k 1 "$(left)" docker ps -a --no-trunc --format '{{.ID}} {{.Names}} {{.State}}' 2>/dev/null | head -n "$maxc")
    while read -r id name state; do
      [ "${#id}" -eq 64 ] || continue
      case "$id" in *[!0-9a-f]*) continue ;; esac
      case "$name" in ""|[!A-Za-z0-9]*|*[!A-Za-z0-9_.-]*) continue ;; esac
      case "$state" in created|running|paused|restarting|removing|exited|dead) ;; *) continue ;; esac
      printf 'C %d %s %s %s\n' "$n" "$id" "$name" "$state"
      ids="$ids $id"
      n=$((n + 1))
    done <<EOF
$list
EOF
  fi
  lj=$lines
  ld=$lines
  b=$(( cap / 2 / jcut ))
  if [ "$lj" -gt "$b" ]; then lj=$b; fi
  if [ "$n" -gt 0 ]; then
    b=$(( cap / 2 / (n * dcut) ))
    if [ "$b" -lt 1 ]; then b=1; fi
    if [ "$ld" -gt "$b" ]; then ld=$b; fi
  fi
  echo "L $lj $ld"
  if [ "$jread" = 1 ]; then
    set -- --no-pager -o json --output-fields=MESSAGE,_SYSTEMD_UNIT,SYSLOG_IDENTIFIER
    if [ -n "$jcursor" ] && [ "$jinclusive" = 1 ]; then
      set -- "$@" "--cursor=$jcursor"
    elif [ -n "$jcursor" ]; then
      set -- "$@" "--after-cursor=$jcursor"
    else
      if [ "$jsince" -gt 0 ]; then set -- "$@" "--since=@$jsince"; fi
      if [ "$tail" -gt 0 ]; then set -- "$@" -n "$tail"; fi
    fi
    for u in $units; do set -- "$@" -u "$u"; done
    rc=$(run_source "$lj" "$jcut" J 0 journalctl "$@")
    echo "E J ${rc:-255}"
  fi
  if [ "$dread" = 1 ]; then
    i=0
    for id in $ids; do
      set -- logs -t
      if [ "$dsince" != 0 ]; then set -- "$@" --since "$dsince"; fi
      if [ "$tail" -gt 0 ]; then set -- "$@" --tail "$tail"; fi
      rc=$(run_source "$ld" "$dcut" "D $i" 1 docker "$@" "$id")
      echo "E D $i ${rc:-255}"
      i=$((i + 1))
    done
  fi
}
collect | head -c "$cap"
`

// Script renders the collection script for sp.
func Script(sp ScriptParams) string {
	cursor := sp.JournalCursor
	if !ValidJournalCursor(cursor) {
		cursor = ""
	}
	var units []string
	for _, u := range sp.Units {
		if unitPattern.MatchString(u) {
			units = append(units, u)
		}
	}
	dsince := "0"
	if sp.ContainerSince > 0 {
		dsince = fmt.Sprintf("%d.%09d", sp.ContainerSince/1e9, sp.ContainerSince%1e9)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# containarium box logs collector (#3643)\n")
	fmt.Fprintf(&b, "root=%s\n", shellQuote(sp.Root))
	fmt.Fprintf(&b, "end=$(( $(date +%%s) + %d ))\n", min(max(sp.Budget, 1), 60))
	fmt.Fprintf(&b, "lines=%d\ntail=%d\n", min(max(sp.Lines, 1), 4*MaxLinesLimit), min(max(sp.Tail, 0), MaxLinesLimit))
	fmt.Fprintf(&b, "jread=%d\ndread=%d\n", boolInt(sp.ReadJournal), boolInt(sp.ReadContainers))
	fmt.Fprintf(&b, "jcursor=%s\njinclusive=%d\njsince=%d\n", shellQuote(cursor), boolInt(sp.JournalInclusive && cursor != ""), max(sp.JournalSince, 0))
	fmt.Fprintf(&b, "dsince=%s\nunits=%s\n", dsince, shellQuote(strings.Join(units, " ")))
	fmt.Fprintf(&b, "cap=%d\njcut=%d\ndcut=%d\nmaxc=%d\n", OutputCap, journalFrameCut, dockerFrameCut, MaxContainers)
	b.WriteString(scriptBody)
	return b.String()
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// shellQuote single-quotes s for sh.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
