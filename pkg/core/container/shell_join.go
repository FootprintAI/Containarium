package container

import "strings"

// shellQuote wraps s in single quotes for POSIX sh, escaping embedded
// single quotes ('foo'\''bar'). Inside single quotes the shell expands
// nothing, so the result is injection-safe for any input, including a
// username crafted to break out of the quoting.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// shellJoin renders argv as one safely-quoted sh command word sequence.
// Used to fold several Exec round-trips into a single `sh -c` script:
// each in-guest Exec is a websocket-upgrading Incus operation at
// ~50-150ms apiece (Finding 2 in
// docs/architecture/two-digit-ms-sandbox-spawn.md), so the join buys
// one round-trip where there were several.
func shellJoin(argv []string) string {
	quoted := make([]string, len(argv))
	for i, a := range argv {
		quoted[i] = shellQuote(a)
	}
	return strings.Join(quoted, " ")
}
