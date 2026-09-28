package engine

import (
	"encoding/json"
	"fmt"
)

// CodeConfigVersion is the version this reader understands. Contract C4.
const CodeConfigVersion = 1

// CodeConfigPath is where `code install` leaves the record and `code run` reads
// it back, 0600. Absolute-from-$HOME because these strings are interpolated into
// shell scripts, not expanded by Go.
const CodeConfigPath = "$HOME/.containarium/code.json"

// CodeConfig is the record `code install` writes on the box so `code run` never
// has to re-ask which engine, credential source, provider, or model this box was
// set up with (contract C4).
//
// It exists because the alternative is flags on every run: `code run <box>
// --engine pi --credential gateway --provider kafeido --model …`, which a user
// would have to keep in sync with what install actually did. Recording it once
// means a wrong answer is impossible rather than merely unlikely.
type CodeConfig struct {
	Version    int    `json:"version"`
	Engine     Name   `json:"engine"`
	Credential Kind   `json:"credential"`
	Provider   string `json:"provider,omitempty"` // gateway only
	Model      string `json:"model,omitempty"`
	SecretName string `json:"secret_name,omitempty"` // secret only
}

// Marshal renders the record for the box. Indented because a human debugging a
// box will `cat` this file, and it is small enough that the bytes do not matter.
func (c CodeConfig) Marshal() ([]byte, error) {
	if c.Version == 0 {
		c.Version = CodeConfigVersion
	}
	blob, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("render code.json: %w", err)
	}
	return append(blob, '\n'), nil
}

// ParseCodeConfig reads a record written by `code install`.
//
// A record from a NEWER containarium is refused rather than reinterpreted. That
// is the forward-compatibility contract, and refusing is the compatible
// behaviour: a v1 reader that silently ignored a v2 field would happily run with
// a credential source that no longer means what it did — the failure would
// surface as someone else's key being billed, not as an error. Failing here
// costs the user one `containarium upgrade`.
func ParseCodeConfig(blob []byte) (*CodeConfig, error) {
	var probe struct {
		Version *int `json:"version"`
	}
	if err := json.Unmarshal(blob, &probe); err != nil {
		return nil, fmt.Errorf("parse %s: %w", CodeConfigPath, err)
	}
	if probe.Version == nil {
		return nil, fmt.Errorf("%s has no \"version\" field — rewrite it with `containarium code install`", CodeConfigPath)
	}
	if *probe.Version > CodeConfigVersion {
		return nil, fmt.Errorf(
			"%s is version %d but this containarium understands version %d — upgrade the CLI (`containarium version` shows yours)",
			CodeConfigPath, *probe.Version, CodeConfigVersion)
	}
	if *probe.Version < 1 {
		return nil, fmt.Errorf("%s has version %d, which is not a valid version", CodeConfigPath, *probe.Version)
	}

	var cfg CodeConfig
	if err := json.Unmarshal(blob, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", CodeConfigPath, err)
	}
	if _, err := ParseName(string(cfg.Engine)); err != nil {
		return nil, fmt.Errorf("%s: %w", CodeConfigPath, err)
	}
	if _, err := ParseCredentialKind(string(cfg.Credential)); err != nil {
		return nil, fmt.Errorf("%s: %w", CodeConfigPath, err)
	}
	if cfg.Credential == KindGateway && cfg.Provider == "" {
		return nil, fmt.Errorf(
			"%s selects the gateway credential but records no provider — rewrite it with `containarium code install <box> --engine %s --credential gateway --provider <name>`",
			CodeConfigPath, cfg.Engine)
	}
	return &cfg, nil
}

// CredentialSource rebuilds the live source this record describes, so `code run`
// can construct the same Engine `code install` did.
func (c CodeConfig) CredentialSource() (CredentialSource, error) {
	switch c.Credential {
	case KindGateway:
		return GatewayCredential{Provider: c.Provider}, nil
	case KindSecret:
		return SecretCredential{Name: c.SecretName}, nil
	default:
		return nil, fmt.Errorf("unknown credential source %q in %s", c.Credential, CodeConfigPath)
	}
}

// EngineFor rebuilds the Engine this record describes.
func (c CodeConfig) EngineFor() (Engine, error) {
	src, err := c.CredentialSource()
	if err != nil {
		return nil, err
	}
	return For(c.Engine, Options{Credential: src, Model: c.Model})
}
