package guardrail

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Placeholder tokens look like [[EMAIL:1a2b3c4d5e6f]]: the engine's type
// name, then 12 hex characters of an HMAC over (kind, type, value) under a
// key that never leaves the side that ran the guardrail. Same value, same
// token — joins across documents survive — while the token alone says
// nothing about the value. The format is also what the gate recognises as
// "already redacted" when it re-scans (see placeholderRE).
var placeholderRE = regexp.MustCompile(`\[\[[A-Z0-9_]+:[0-9a-f]{12}\]\]`)

// VaultEntry is the original behind one token. The vault is the only
// re-identification path; it stays with the key, on the data owner's side.
type VaultEntry struct {
	Kind  pb.GuardrailKind `json:"kind"`
	Type  string           `json:"type"`
	Value string           `json:"value"`
}

// Vault maps placeholder token -> original. SECRET findings are redacted
// but never vaulted: a persisted store of credentials, however encrypted,
// is a risk class this flow does not take on.
type Vault map[string]VaultEntry

// RedactResult is what Redact produced for one run.
type RedactResult struct {
	// Wiped text per unit id, including units that had no findings.
	Wiped map[string]string
	Vault Vault
	// Findings on the original, per kind, before any action.
	Found map[pb.GuardrailKind]int64
	// Findings whose kind the policy marks BLOCK. Any non-zero count fails
	// the gate regardless of what the re-scan says.
	Blocked map[pb.GuardrailKind]int64
}

type span struct {
	start, end int
	kind       pb.GuardrailKind
	typ        string
	conf       float64
}

// Redact applies policy to the engine's findings over units and returns
// the wiped text, the vault and the counts the gate and the attestation
// need. Offsets are code points, so each unit is sliced as []rune.
func Redact(units []*pb.GuardrailTextUnit, findings []*pb.GuardrailFinding, policy *pb.GuardrailPolicy, key []byte) (*RedactResult, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("guardrail: redaction key is empty")
	}
	actions := actionsByKind(policy)
	byUnit := map[string][]span{}
	res := &RedactResult{
		Wiped:   map[string]string{},
		Vault:   Vault{},
		Found:   map[pb.GuardrailKind]int64{},
		Blocked: map[pb.GuardrailKind]int64{},
	}
	for _, f := range findings {
		res.Found[f.GetKind()]++
		switch actions[f.GetKind()] {
		case pb.GuardrailAction_GUARDRAIL_ACTION_BLOCK:
			res.Blocked[f.GetKind()]++
		case pb.GuardrailAction_GUARDRAIL_ACTION_REDACT:
			byUnit[f.GetUnitId()] = append(byUnit[f.GetUnitId()], span{
				int(f.GetStart()), int(f.GetEnd()), f.GetKind(), f.GetType(), f.GetConfidence()})
		}
	}
	for _, u := range units {
		runes := []rune(u.GetText())
		spans := mergeSpans(byUnit[u.GetUnitId()])
		for _, s := range spans {
			if s.start < 0 || s.end > len(runes) || s.start >= s.end {
				return nil, fmt.Errorf("guardrail: finding [%d,%d) out of range for unit %q (len %d code points)", s.start, s.end, u.GetUnitId(), len(runes))
			}
		}
		// Back to front so earlier offsets stay valid.
		out := runes
		for i := len(spans) - 1; i >= 0; i-- {
			s := spans[i]
			value := string(runes[s.start:s.end])
			tok := Token(key, s.kind, s.typ, value)
			if s.kind != pb.GuardrailKind_GUARDRAIL_KIND_SECRET {
				res.Vault[tok] = VaultEntry{Kind: s.kind, Type: s.typ, Value: value}
			}
			repl := []rune(tok)
			next := make([]rune, 0, len(out)-(s.end-s.start)+len(repl))
			next = append(next, out[:s.start]...)
			next = append(next, repl...)
			next = append(next, out[s.end:]...)
			out = next
		}
		res.Wiped[u.GetUnitId()] = string(out)
	}
	return res, nil
}

// Token is the placeholder for one (kind, type, value) under key.
func Token(key []byte, kind pb.GuardrailKind, typ, value string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(kind.String()))
	mac.Write([]byte{0x1f})
	mac.Write([]byte(typ))
	mac.Write([]byte{0x1f})
	mac.Write([]byte(value))
	sum := mac.Sum(nil)
	return fmt.Sprintf("[[%s:%s]]", typ, hex.EncodeToString(sum[:6]))
}

// mergeSpans collapses overlapping or touching spans into one; the
// surviving type is the higher-confidence member's.
func mergeSpans(in []span) []span {
	if len(in) == 0 {
		return nil
	}
	sort.Slice(in, func(i, j int) bool {
		if in[i].start != in[j].start {
			return in[i].start < in[j].start
		}
		return in[i].end > in[j].end
	})
	out := []span{in[0]}
	for _, s := range in[1:] {
		last := &out[len(out)-1]
		if s.start <= last.end {
			if s.end > last.end {
				last.end = s.end
			}
			if s.conf > last.conf {
				last.kind, last.typ, last.conf = s.kind, s.typ, s.conf
			}
			continue
		}
		out = append(out, s)
	}
	return out
}

// actionsByKind flattens a policy. A kind the policy does not mention gets
// REDACT: silently allowing an unlisted kind is the wrong default for a
// guardrail.
func actionsByKind(policy *pb.GuardrailPolicy) map[pb.GuardrailKind]pb.GuardrailAction {
	out := map[pb.GuardrailKind]pb.GuardrailAction{}
	for _, r := range policy.GetRules() {
		out[r.GetKind()] = r.GetAction()
	}
	for _, k := range []pb.GuardrailKind{pb.GuardrailKind_GUARDRAIL_KIND_PII, pb.GuardrailKind_GUARDRAIL_KIND_SECRET} {
		if _, ok := out[k]; !ok {
			out[k] = pb.GuardrailAction_GUARDRAIL_ACTION_REDACT
		}
	}
	return out
}

// DefaultPolicy redacts every kind and tolerates no residual.
func DefaultPolicy() *pb.GuardrailPolicy {
	return &pb.GuardrailPolicy{Rules: []*pb.GuardrailRule{
		{Kind: pb.GuardrailKind_GUARDRAIL_KIND_PII, Action: pb.GuardrailAction_GUARDRAIL_ACTION_REDACT},
		{Kind: pb.GuardrailKind_GUARDRAIL_KIND_SECRET, Action: pb.GuardrailAction_GUARDRAIL_ACTION_REDACT},
	}}
}
