package audit

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Parsing dropbear's login lines (#1189).
//
// K8s boxes run dropbear, not OpenSSH, and the two log successful
// authentication in completely different words. The existing sshd parser
// matches "Accepted publickey for alice from 10.0.0.1 port 54321"; dropbear
// never emits that string, so an sshd-shaped parser pointed at a K8s box
// silently yields zero login records — indistinguishable from a box nobody
// logged into.
//
// The formats below are taken from the dropbear binary's own format strings
// (2022.83), not from documentation or memory:
//
//	Password auth succeeded for '%s' from %s
//	Pubkey auth succeeded for '%s' with %s key %s from %s
//	Auth succeeded with blank password for '%s' from %s
//
// Note the shape differences that matter for a regex: the username is
// single-quoted, the source is host:port rather than "from IP port N", and
// the method word comes FIRST rather than after "Accepted".

var (
	// dropbearPubkeyPattern: Pubkey auth succeeded for 'alice' with ssh-ed25519 key SHA256:... from 10.0.0.1:54321
	dropbearPubkeyPattern = regexp.MustCompile(
		`Pubkey auth succeeded for '([^']+)' with \S+ key \S+ from (\S+)`,
	)
	// dropbearPasswordPattern: Password auth succeeded for 'alice' from 10.0.0.1:54321
	dropbearPasswordPattern = regexp.MustCompile(
		`Password auth succeeded for '([^']+)' from (\S+)`,
	)
	// dropbearBlankPattern: Auth succeeded with blank password for 'alice' from 10.0.0.1:54321
	//
	// Worth capturing rather than ignoring: a blank-password login is the one
	// an auditor most wants to see, and dropping it because it does not look
	// like the other two would hide exactly the wrong event.
	dropbearBlankPattern = regexp.MustCompile(
		`Auth succeeded with blank password for '([^']+)' from (\S+)`,
	)
)

// dropbearTimestampPattern matches the leading syslog-style timestamp that
// dropbear emits when logging to stderr, e.g.
// "[123] Mar 12 14:30:01 Pubkey auth succeeded ...". Absent when the runtime
// strips it, which is why parsing tolerates its absence.
var dropbearTimestampPattern = regexp.MustCompile(
	`(?:\[\d+\]\s+)?(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s`,
)

// parseDropbearLine extracts a successful login from one dropbear log line.
//
// fallback is used when the line carries no timestamp — the pod log API can
// supply one per line, and a record with the wrong time is worse than one
// with an approximate time clearly derived from the reader.
func parseDropbearLine(line string, year int, fallback time.Time) (ts time.Time, user, source, method string, ok bool) {
	switch {
	case dropbearPubkeyPattern.MatchString(line):
		m := dropbearPubkeyPattern.FindStringSubmatch(line)
		user, source, method = m[1], m[2], "publickey"
	case dropbearPasswordPattern.MatchString(line):
		m := dropbearPasswordPattern.FindStringSubmatch(line)
		user, source, method = m[1], m[2], "password"
	case dropbearBlankPattern.MatchString(line):
		m := dropbearBlankPattern.FindStringSubmatch(line)
		user, source, method = m[1], m[2], "blank-password"
	default:
		return time.Time{}, "", "", "", false
	}

	// dropbear reports host:port; the audit record wants the host. Trim the
	// port rather than storing "10.0.0.1:54321" as an address, which would
	// break every query that groups by source.
	source = trimSourcePort(source)

	return parseDropbearTimestamp(line, year, fallback), user, source, method, true
}

// parseDropbearTimestamp reads the line's own timestamp, falling back to the
// supplied one.
func parseDropbearTimestamp(line string, year int, fallback time.Time) time.Time {
	m := dropbearTimestampPattern.FindStringSubmatch(line)
	if m == nil {
		return fallback
	}
	tsStr := fmt.Sprintf("%d %s", year, m[1])
	// Two layouts because the day is space-padded for single digits in some
	// runtimes and not others.
	for _, layout := range []string{"2006 Jan  2 15:04:05", "2006 Jan 2 15:04:05"} {
		if ts, err := time.Parse(layout, tsStr); err == nil {
			return ts
		}
	}
	return fallback
}

// trimSourcePort turns "10.0.0.1:54321" into "10.0.0.1", leaving a bare
// address (and IPv6 forms) alone.
func trimSourcePort(source string) string {
	// IPv6 with port is bracketed: [::1]:54321
	if strings.HasPrefix(source, "[") {
		if end := strings.LastIndex(source, "]"); end > 0 {
			return source[1:end]
		}
		return source
	}
	// Exactly one colon means host:port; more means a bare IPv6 address.
	if strings.Count(source, ":") == 1 {
		if host, _, found := strings.Cut(source, ":"); found {
			return host
		}
	}
	return source
}
