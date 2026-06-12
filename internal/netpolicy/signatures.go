package netpolicy

import (
	"fmt"
	"strings"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Tier 2 (#661) — curated cleartext exploit signatures shipped with the daemon.
//
// These are matched (best-effort) against the first window of an INBOUND TCP
// payload by the eBPF egress program to virtually-patch a vulnerable service in
// a container before the vendor fix ships. The set is deliberately small and
// high-confidence: each pattern is a literal byte string that is strong evidence
// of an exploit attempt and rare in legitimate cleartext traffic. Operator-
// managed signatures (PR-B) augment this built-in baseline.
//
// Constraints (mirror the BPF program): a pattern must be 1..32 bytes; up to 32
// signatures are scanned. IDs are stable and nonzero (echoed in the audit on a
// match) — never renumber a shipped signature.

// SigMaxLen mirrors the BPF program's per-pattern byte limit (netbpf.SigMaxLen).
// Duplicated here so this pure package validates operator input without
// importing netbpf; a divergence is caught by a cross-package test in server.
const SigMaxLen = 32

// OperatorIDBase is the first id assigned to operator signatures (#661 PR-B).
// Built-in ids live below it (1..), so operator and built-in ids never collide
// and a match's audit id unambiguously names its source.
const OperatorIDBase = 1000

// Signature is one cleartext exploit pattern. Pattern is the raw bytes to
// substring-match; Name labels it in audit logs.
type Signature struct {
	ID      uint16
	Name    string
	Pattern []byte
}

// ValidateSignature checks an operator-supplied signature (#661 PR-B): a
// non-empty name (no whitespace or '/', so it works as a URL path segment for
// delete) and a 1..SigMaxLen byte pattern. It does NOT assign the id (the store
// does) and returns the trimmed name + pattern bytes ready to store.
func ValidateSignature(s *pb.NetworkPolicySignature) (name string, pattern []byte, err error) {
	if s == nil {
		return "", nil, fmt.Errorf("signature is nil")
	}
	name = strings.TrimSpace(s.GetName())
	if name == "" {
		return "", nil, fmt.Errorf("signature: name is required")
	}
	if strings.ContainsAny(name, " \t/") {
		return "", nil, fmt.Errorf("signature: name %q must not contain whitespace or '/'", name)
	}
	pattern = []byte(s.GetPattern())
	if len(pattern) == 0 {
		return "", nil, fmt.Errorf("signature %q: pattern is required", name)
	}
	if len(pattern) > SigMaxLen {
		return "", nil, fmt.Errorf("signature %q: pattern is %d bytes, max %d", name, len(pattern), SigMaxLen)
	}
	return name, pattern, nil
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
