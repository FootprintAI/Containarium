package engine

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestCodeConfigRoundTrip is the AC's round-trip test for the record `code
// install` leaves on the box and `code run` reads back.
func TestCodeConfigRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		cfg  CodeConfig
	}{
		{
			name: "pi on the gateway",
			cfg: CodeConfig{
				Version:    CodeConfigVersion,
				Engine:     NamePi,
				Credential: KindGateway,
				Provider:   "kafeido",
				Model:      "kafeido-coder",
			},
		},
		{
			name: "pi on a tenant secret",
			cfg: CodeConfig{
				Version:    CodeConfigVersion,
				Engine:     NamePi,
				Credential: KindSecret,
				SecretName: "ANTHROPIC_API_KEY",
				Model:      "claude-sonnet-5",
			},
		},
		{
			name: "claude, the default",
			cfg: CodeConfig{
				Version:    CodeConfigVersion,
				Engine:     NameClaude,
				Credential: KindSecret,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			blob, err := tc.cfg.Marshal()
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			got, err := ParseCodeConfig(blob)
			if err != nil {
				t.Fatalf("ParseCodeConfig: %v", err)
			}
			if *got != tc.cfg {
				t.Errorf("round-trip mismatch\n got: %+v\nwant: %+v", *got, tc.cfg)
			}

			// The omitempty fields must actually be omitted, so a claude
			// record doesn't carry an empty "provider" that reads as
			// meaningful.
			var raw map[string]any
			if err := json.Unmarshal(blob, &raw); err != nil {
				t.Fatalf("unmarshal raw: %v", err)
			}
			if tc.cfg.Provider == "" {
				if _, ok := raw["provider"]; ok {
					t.Errorf("empty provider should be omitted, got %s", blob)
				}
			}
			if tc.cfg.SecretName == "" {
				if _, ok := raw["secret_name"]; ok {
					t.Errorf("empty secret_name should be omitted, got %s", blob)
				}
			}
		})
	}
}

// TestCodeConfigRoundTrip_NewerVersionFailsLoudly is the forward-compat half of
// the AC. A record written by a NEWER containarium must be refused with a
// message naming the fix — never silently reinterpreted as v1.
//
// The design doc (C4) and the issue phrase this differently ("fails loudly" vs
// "forward-compat"); failing loudly IS the forward-compat contract here,
// because the alternative is a v1 reader quietly ignoring a v2 field that
// changed what the record means — e.g. a future `credential: "oidc"` read as
// no credential at all.
func TestCodeConfigRoundTrip_NewerVersionFailsLoudly(t *testing.T) {
	newer := []byte(`{
	  "version": 2,
	  "engine": "pi",
	  "credential": "gateway",
	  "provider": "kafeido",
	  "model": "kafeido-coder",
	  "some_field_v1_has_never_heard_of": {"nested": true}
	}`)

	got, err := ParseCodeConfig(newer)
	if err == nil {
		t.Fatalf("a version-2 record was accepted by the v1 reader: %+v", got)
	}
	for _, want := range []string{"2", "upgrade"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should name the version and the fix (missing %q): %v", want, err)
		}
	}
}

func TestParseCodeConfig_Rejections(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "no version at all",
			in:   `{"engine":"pi","credential":"gateway"}`,
			want: "version",
		},
		{
			name: "unknown engine",
			in:   `{"version":1,"engine":"codex","credential":"gateway"}`,
			want: "codex",
		},
		{
			name: "unknown credential source",
			in:   `{"version":1,"engine":"pi","credential":"oauth"}`,
			want: "oauth",
		},
		{
			name: "gateway with no provider",
			in:   `{"version":1,"engine":"pi","credential":"gateway"}`,
			want: "provider",
		},
		{
			name: "not JSON at all",
			in:   `this is not json`,
			want: "code.json",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseCodeConfig([]byte(tc.in))
			if err == nil {
				t.Fatalf("expected an error for %s", tc.in)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q should mention %q", err, tc.want)
			}
		})
	}
}

// TestCodeConfig_CredentialSourceRoundTrips proves the record is enough to
// rebuild the live CredentialSource `code run` needs — otherwise run would have
// to re-ask the user for flags install already recorded.
func TestCodeConfig_CredentialSourceRoundTrips(t *testing.T) {
	gw := CodeConfig{Version: 1, Engine: NamePi, Credential: KindGateway, Provider: "kafeido"}
	src, err := gw.CredentialSource()
	if err != nil {
		t.Fatalf("CredentialSource: %v", err)
	}
	if src.Kind() != KindGateway || src.Preflight() != PreflightGatewayDryRun {
		t.Errorf("gateway record rebuilt as %v/%v", src.Kind(), src.Preflight())
	}

	sec := CodeConfig{Version: 1, Engine: NamePi, Credential: KindSecret, SecretName: "OPENAI_API_KEY"}
	src, err = sec.CredentialSource()
	if err != nil {
		t.Fatalf("CredentialSource: %v", err)
	}
	if src.Kind() != KindSecret {
		t.Errorf("secret record rebuilt as %v", src.Kind())
	}
}

// TestCodeConfigPath pins where the record lives, since install writes it over
// SSH and run reads it back over a different connection.
func TestCodeConfigPath(t *testing.T) {
	if CodeConfigPath != "$HOME/.containarium/code.json" {
		t.Errorf("CodeConfigPath = %q, want $HOME/.containarium/code.json (contract C4)", CodeConfigPath)
	}
}
