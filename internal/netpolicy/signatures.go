package netpolicy

// Tier 2 (#661) — curated cleartext exploit signatures shipped with the daemon.
//
// These are matched (best-effort) against the first window of an INBOUND TCP
// payload by the eBPF egress program to virtually-patch a vulnerable service in
// a container before the vendor fix ships. The set is deliberately small and
// high-confidence: each pattern is a literal byte string that is strong evidence
// of an exploit attempt and rare in legitimate cleartext traffic. Operator-
// managed signatures (add/remove via the API) are a later increment (PR-B); this
// is the built-in baseline.
//
// Constraints (mirror the BPF program): a pattern must be 1..32 bytes; up to 32
// signatures are scanned. IDs are stable and nonzero (echoed in the audit on a
// match) — never renumber a shipped signature.

// Signature is one cleartext exploit pattern. Pattern is the raw bytes to
// substring-match; Name labels it in audit logs.
type Signature struct {
	ID      uint16
	Name    string
	Pattern []byte
}

// BuiltinSignatures returns the daemon's curated signature set. Order is not
// significant (every slot is scanned); IDs are the stable identity.
func BuiltinSignatures() []Signature {
	return []Signature{
		// Log4Shell (CVE-2021-44228): the JNDI lookup prefix in any header/body.
		{ID: 1, Name: "log4shell-jndi", Pattern: []byte("${jndi:")},
		// Shellshock (CVE-2014-6271): the function-definition prelude in a header.
		{ID: 2, Name: "shellshock", Pattern: []byte("() {")},
		// Spring4Shell (CVE-2022-22965): classLoader property traversal.
		{ID: 3, Name: "spring4shell", Pattern: []byte("class.module.classLoader")},
		// Directory traversal: a run of parent-dir escapes.
		{ID: 4, Name: "path-traversal", Pattern: []byte("../../../")},
		// A common traversal target.
		{ID: 5, Name: "etc-passwd", Pattern: []byte("/etc/passwd")},
	}
}
