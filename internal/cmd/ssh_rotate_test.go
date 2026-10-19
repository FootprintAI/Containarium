package cmd

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/footprintai/containarium/internal/sshconfig"
	"github.com/footprintai/containarium/internal/sshkey"
	"github.com/footprintai/containarium/pkg/core/incus"
	"golang.org/x/crypto/ssh"
)

func TestSSHRotate_CommandRegistered(t *testing.T) {
	cmd, _, err := sshCmd.Find([]string{"rotate"})
	if err != nil || cmd.Name() != "rotate" {
		t.Fatalf("ssh rotate command missing: command=%q, error=%v", cmd.Name(), err)
	}
	if cmd.RunE == nil || cmd.Flags().Lookup("name") == nil || cmd.Flags().Lookup("server") == nil {
		t.Fatal("ssh rotate must have a handler and name/server flags")
	}
}

// Verify the shipped cloud contract independently of the CLI signer.
func verifyRotationProof(publicKey string, signature, nonce []byte) error {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(publicKey))
	if err != nil {
		return err
	}
	var sig ssh.Signature
	if err := ssh.Unmarshal(signature, &sig); err != nil {
		return err
	}
	return pub.Verify(append([]byte("containarium-ssh-key-proof-v1\x00"), nonce...), &sig)
}

func TestSSHRotate_HTTPFlow(t *testing.T) {
	for _, tc := range []struct {
		name                                            string
		challengeStatus, registrationStatus             int
		listStatus                                      int
		challengeBody, registrationBody, listBody       string
		wantOverlap                                     string
		wantErr, snakeCaseChallenge, wantNoRegistration bool
	}{
		{name: "success with key-only registration response"},
		{name: "snake_case challenge response", snakeCaseChallenge: true},
		{name: "signature rejected", registrationStatus: 400, wantErr: true},
		{name: "challenge unimplemented", challengeStatus: 501, wantErr: true, wantNoRegistration: true},
		{name: "challenge absent", challengeStatus: 404, wantErr: true, wantNoRegistration: true},
		{name: "challenge missing ID", challengeBody: `{"nonce":"AP8qEYABCQo="}`, wantErr: true, wantNoRegistration: true},
		{name: "challenge missing nonce", challengeBody: `{"challengeId":"challenge-1"}`, wantErr: true, wantNoRegistration: true},
		{name: "challenge empty nonce", challengeBody: `{"challengeId":"challenge-1","nonce":""}`, wantErr: true, wantNoRegistration: true},
		{name: "challenge invalid base64", challengeBody: `{"challengeId":"challenge-1","nonce":"%%%"}`, wantErr: true, wantNoRegistration: true},
		{name: "challenge malformed", challengeBody: `{`, wantErr: true, wantNoRegistration: true},
		{name: "wrong fingerprint", registrationBody: `{"key":{"fingerprint":"SHA256:other"}}`, wantErr: true},
		{name: "missing fingerprint", registrationBody: `{"key":{"name":"laptop"}}`, wantErr: true},
		{name: "registration missing key", registrationBody: `{}`, wantErr: true},
		{name: "registration null key", registrationBody: `{"key":null}`, wantErr: true},
		{name: "registration malformed", registrationBody: `{`, wantErr: true},
		{name: "registration conflict", registrationStatus: http.StatusConflict, wantErr: true},
		{name: "list unavailable", listStatus: 503, wantOverlap: "overlap end is unknown"},
		{name: "list malformed", listBody: `{`, wantOverlap: "overlap end is unknown"},
		{name: "invalid retirement timestamp", listBody: `{"keys":[{"name":"laptop","fingerprint":"$OLD","retiredAt":"invalid"}]}`, wantOverlap: "overlap end is unknown"},
		{name: "previous key missing", listBody: `{"keys":[]}`, wantOverlap: "overlap end is unknown"},
		{name: "retirement missing", listBody: `{"keys":[{"name":"laptop","fingerprint":"$OLD","retiredAt":null}]}`, wantOverlap: "overlap end is unknown"},
		{name: "snake_case retirement", listBody: `{"keys":[{"name":"laptop","fingerprint":"$OLD","retired_at":"2026-10-20T00:00:00Z"}]}`},
		{name: "another device retired", listBody: `{"keys":[{"name":"desktop","fingerprint":"$OLD","retiredAt":"2026-10-20T00:00:00Z"}]}`, wantOverlap: "overlap end is unknown"},
		{name: "new key retirement ignored", listBody: `{"keys":[{"name":"laptop","fingerprint":"$NEW","retiredAt":"2026-10-20T00:00:00Z"}]}`, wantOverlap: "overlap end is unknown"},
		{name: "latest previous retirement", listBody: `{"keys":[{"name":"desktop","fingerprint":"SHA256:desktop","retiredAt":"2027-01-01T00:00:00Z"},{"name":"laptop","fingerprint":"$OLD","retiredAt":"2026-10-20T00:00:00Z"},{"name":"laptop","fingerprint":"SHA256:older","retiredAt":"2026-10-01T00:00:00Z"}]}`},
	} {
		if tc.challengeStatus == 0 {
			tc.challengeStatus = http.StatusOK
		}
		if tc.registrationStatus == 0 {
			tc.registrationStatus = http.StatusOK
		}
		if tc.listStatus == 0 {
			tc.listStatus = http.StatusOK
		}
		if tc.listBody == "" {
			tc.listBody = `{"keys":[{"name":"laptop","fingerprint":"$NEW","retiredAt":null},{"name":"laptop","fingerprint":"$OLD","retiredAt":"2026-10-20T00:00:00Z"}]}`
		}
		if tc.wantOverlap == "" {
			tc.wantOverlap = "overlap ends at 2026-10-20T00:00:00Z"
		}
		t.Run(tc.name, func(t *testing.T) {
			home := withSSHHome(t)
			oldPubPath, oldPub, err := sshkey.Generate(sshkey.LocateOpts{HomeDir: home}, false)
			if err != nil {
				t.Fatal(err)
			}
			oldFingerprint, err := sshkey.Fingerprint(oldPub)
			if err != nil {
				t.Fatal(err)
			}
			oldPath := strings.TrimSuffix(oldPubPath, ".pub")
			oldKey, err := os.ReadFile(oldPath)
			if err != nil {
				t.Fatal(err)
			}
			configPath := filepath.Join(home, ".containarium", "ssh_config")
			g := sshconfig.Generate([]incus.ContainerInfo{{Name: "box", State: "Running"}}, sshconfig.Options{Sentinel: "sentinel.example.com", IdentityFile: oldPath})
			if _, err := sshconfig.WriteConfig(configPath, g, false); err != nil {
				t.Fatal(err)
			}
			nonce := []byte{0, 255, 42, 17, 128, 1, 9, 10}
			var challenges, registrations, lists atomic.Int32
			var postedPublic atomic.Value
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer rotate-token" {
					t.Error("wrong rotation credential")
				}
				switch r.URL.Path {
				case "/v1/user/ssh-keys:challenge":
					if r.Method != http.MethodPost {
						t.Errorf("wrong challenge method: %s", r.Method)
					}
					challenges.Add(1)
					w.WriteHeader(tc.challengeStatus)
					if tc.challengeStatus == 200 {
						if tc.challengeBody != "" {
							_, _ = w.Write([]byte(tc.challengeBody))
							return
						}
						field := "challengeId"
						if tc.snakeCaseChallenge {
							field = "challenge_id"
						}
						fmt.Fprintf(w, `{"%s":"challenge-1","nonce":%q}`, field, base64.StdEncoding.EncodeToString(nonce))
					}
				case "/v1/user/ssh-keys":
					if r.Method == http.MethodGet {
						lists.Add(1)
						config, err := os.ReadFile(configPath)
						if err != nil || string(config) == g.Content {
							t.Errorf("new key must be selected before the best-effort list request: %v", err)
						}
						w.WriteHeader(tc.listStatus)
						if tc.listStatus == http.StatusOK {
							fp, _ := sshkey.Fingerprint(postedPublic.Load().(string))
							body := strings.NewReplacer("$OLD", oldFingerprint, "$NEW", fp).Replace(tc.listBody)
							_, _ = w.Write([]byte(body))
						}
						return
					}
					if r.Method != http.MethodPost {
						t.Errorf("wrong registration method: %s", r.Method)
					}
					registrations.Add(1)
					config, err := os.ReadFile(configPath)
					if err != nil || string(config) != g.Content {
						t.Errorf("config changed before registration was accepted: %v", err)
					}
					var req struct {
						Name        string `json:"name"`
						PublicKey   string `json:"public_key"`
						KeyType     string `json:"key_type"`
						ChallengeID string `json:"challenge_id"`
						Signature   string `json:"signature"`
					}
					if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
						t.Error(err)
						w.WriteHeader(400)
						return
					}
					if req.Name != "laptop" || req.ChallengeID != "challenge-1" || req.KeyType != "SSH_KEY_TYPE_ED25519" {
						t.Errorf("wrong registration fields: %+v", req)
					}
					// A protobuf bytes field must arrive as a standard Base64
					// JSON string, never an array of integers or PEM armor.
					proof, err := base64.StdEncoding.Strict().DecodeString(req.Signature)
					if err != nil {
						t.Errorf("signature is not standard Base64: %v", err)
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					if err := verifyRotationProof(req.PublicKey, proof, nonce); err != nil {
						t.Errorf("bad proof: %v", err)
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					postedPublic.Store(req.PublicKey)
					w.WriteHeader(tc.registrationStatus)
					if tc.registrationStatus == 200 {
						if tc.registrationBody != "" {
							_, _ = w.Write([]byte(tc.registrationBody))
						} else {
							fp, _ := sshkey.Fingerprint(req.PublicKey)
							fmt.Fprintf(w, `{"key":{"name":"laptop","fingerprint":%q,"publicKey":%q,"createdAt":"2026-10-19T00:00:00Z"}}`, fp, req.PublicKey)
						}
					}
				default:
					t.Errorf("unexpected endpoint %s", r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()
			seedTokenFor(t, home, srv.URL, "rotate-token")
			cmd, _, err := sshCmd.Find([]string{"rotate"})
			if err != nil || cmd.Name() != "rotate" {
				t.Fatal("ssh rotate command missing")
			}
			if err := cmd.Flags().Set("name", "laptop"); err != nil {
				t.Fatal(err)
			}
			if err := cmd.Flags().Set("server", srv.URL); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = cmd.Flags().Set("name", ""); _ = cmd.Flags().Set("server", "") })
			var out bytes.Buffer
			cmd.SetOut(&out)
			err = cmd.RunE(cmd, nil)
			if (err != nil) != tc.wantErr {
				t.Fatalf("error=%v, wantErr=%v", err, tc.wantErr)
			}
			after, readErr := os.ReadFile(configPath)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if !tc.wantErr {
				if string(after) == g.Content || strings.Contains(string(after), "IdentityFile "+oldPath+"\n") || !strings.Contains(out.String(), tc.wantOverlap) {
					t.Fatalf("config/overlap not updated:\n%s\n%s", after, out.String())
				}
				files, err := filepath.Glob(filepath.Join(home, ".ssh", "containarium_ed25519_*.pub"))
				if err != nil || len(files) != 1 {
					t.Fatalf("new key files: %v, %v", files, err)
				}
				pub, err := sshkey.ReadPublicKey(files[0])
				if err != nil || pub != postedPublic.Load() || !strings.Contains(string(after), strings.TrimSuffix(files[0], ".pub")) {
					t.Fatal("config does not select the registered key")
				}
			} else if string(after) != g.Content {
				t.Fatal("failure changed ssh_config")
			}
			remaining, keyReadErr := os.ReadFile(oldPath)
			if keyReadErr != nil || !bytes.Equal(oldKey, remaining) {
				t.Fatal("old private key changed or removed")
			}
			if challenges.Load() != 1 {
				t.Fatal("challenge not requested once")
			}
			if tc.challengeStatus != 200 {
				if registrations.Load() != 0 || !strings.Contains(err.Error(), "not supported") {
					t.Fatalf("unimplemented challenge did not fail clearly without registration: %v", err)
				}
			}
			wantRegistrations := int32(1)
			if tc.wantNoRegistration {
				wantRegistrations = 0
			}
			if registrations.Load() != wantRegistrations {
				t.Fatalf("registration requests=%d, want %d", registrations.Load(), wantRegistrations)
			}
			wantLists := int32(1)
			if tc.wantErr {
				wantLists = 0
			}
			if lists.Load() != wantLists {
				t.Fatalf("list requests=%d, want %d", lists.Load(), wantLists)
			}
		})
	}
}
