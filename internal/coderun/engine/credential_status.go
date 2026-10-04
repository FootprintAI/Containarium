package engine

import "fmt"

// Credential-status probe (#2272).
//
// A crew member's box (internal/server's agent-<skill-id>) is now
// provisionable before any inference credential exists — see
// ProvisionSkillBox. Once a human has signed in on it, the ONLY thing
// anything downstream (a human re-checking, or Containarium-cloud's own
// admit() gate, #2109 on that repo) is allowed to learn is WHICH source
// would answer the engine's next run, never the credential's value.
//
// This mirrors #2030's `code install` verify posture exactly (claude.go's
// VerifyScript / pi.go's VerifyScript): every check below is a file's
// existence or an env var's NAME. Nothing here reads, logs, or transmits a
// credential at any layer.
//
// It deliberately does NOT reuse the Engine interface (claudeEngine/
// piEngine, constructed via For(Name, Options)): those require a
// CredentialSource (secret/gateway — containarium's OWN credential
// plumbing, an unrelated axis), which a box provisioned straight from the
// "coding-agent" recipe and never run through `code install` does not
// have. The probe is a pure function of the engine Name alone.

// CredentialStatusSource names WHERE a box's coding engine would currently
// find a sign-in — never the credential's value.
type CredentialStatusSource string

const (
	// CredentialStatusInteractive: the engine's own device-code/browser
	// sign-in has already completed on this box.
	CredentialStatusInteractive CredentialStatusSource = "interactive"
	// CredentialStatusAPIKey: a user-placed provider key/token is visible
	// to the engine's own shell environment — the headless path #2030
	// documents.
	CredentialStatusAPIKey CredentialStatusSource = "api-key"
	// CredentialStatusNone: neither of the above. Expected and normal on a
	// freshly provisioned box (#2272) — never an error on its own.
	CredentialStatusNone CredentialStatusSource = "none"
)

// credentialStatusSources lists every value CredentialStatusScript's
// rendered probe is allowed to print, for ParseCredentialStatusSource.
var credentialStatusSources = []CredentialStatusSource{
	CredentialStatusInteractive, CredentialStatusAPIKey, CredentialStatusNone,
}

// ParseCredentialStatusSource validates a probe's trimmed stdout against the
// three values above. Anything else is an error naming what was seen rather
// than silently defaulting to "none" — a script that printed something else
// means the detection logic and this parser have drifted, which must fail
// loudly, not report a possibly-wrong status.
func ParseCredentialStatusSource(s string) (CredentialStatusSource, error) {
	for _, v := range credentialStatusSources {
		if CredentialStatusSource(s) == v {
			return v, nil
		}
	}
	return "", fmt.Errorf("unrecognized credential-status probe output %q", s)
}

// CredentialStatusScript renders a POSIX script that probes box state for
// the named engine and echoes EXACTLY ONE line: one of the
// CredentialStatusSource values above. ok=false means this engine has no
// probe yet — callers must refuse cleanly, never guess.
func CredentialStatusScript(n Name) (script string, ok bool) {
	switch n {
	case NameClaude:
		return claudeCredentialStatusScript, true
	case NamePi:
		return piCredentialStatusScript, true
	case NameCodex:
		return codexCredentialStatusScript, true
	default:
		return "", false
	}
}
