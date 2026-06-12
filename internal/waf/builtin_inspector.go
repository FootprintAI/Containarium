package waf

import "bytes"

// builtinSig is one cleartext exploit pattern the reference inspector matches.
// The set deliberately mirrors the in-kernel Tier 2 signatures (#661), but is
// defined locally so Tier 3 stays independent of the Tier 2 control plane — the
// two can be de-duplicated once both land. Ids are stable + nonzero (echoed in
// the audit on a block).
type builtinSig struct {
	id      uint16
	name    string
	pattern []byte
}

func builtinSignatures() []builtinSig {
	return []builtinSig{
		{1, "log4shell-jndi", []byte("${jndi:")},
		{2, "shellshock", []byte("() {")},
		{3, "spring4shell", []byte("class.module.classLoader")},
		{4, "path-traversal", []byte("../../../")},
		{5, "etc-passwd", []byte("/etc/passwd")},
	}
}

// BuiltinInspector is the reference Inspector (#662 PR-2): it substring-matches a
// curated set of cleartext exploit signatures over the REASSEMBLED request head —
// so it catches a signature split across TCP segments that the in-kernel
// single-packet scan (Tier 2) cannot. No WAF-engine dependency; the Coraza-backed
// inspector (full HTTP parse + OWASP CRS) is a follow-up behind the same
// interface and a `waf` build tag.
type BuiltinInspector struct {
	sigs []builtinSig
}

// NewBuiltinInspector builds the reference inspector from the curated set.
func NewBuiltinInspector() *BuiltinInspector {
	return &BuiltinInspector{sigs: builtinSignatures()}
}

// Inspect blocks on the first signature whose pattern appears anywhere in the
// reassembled head.
func (b *BuiltinInspector) Inspect(head []byte) Verdict {
	for _, s := range b.sigs {
		if len(s.pattern) > 0 && bytes.Contains(head, s.pattern) {
			return Verdict{Block: true, RuleID: s.id, RuleName: s.name}
		}
	}
	return Verdict{}
}
