package cmd

import (
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
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

// Decode the documented SSHSIG format independently of the CLI signer.
func verifyRotationProof(publicKey, signature string, nonce []byte) error {
	block, rest := pem.Decode([]byte(signature))
	if block == nil || block.Type != "SSH SIGNATURE" || len(bytes.TrimSpace(rest)) != 0 {
		return fmt.Errorf("invalid SSHSIG armor")
	}
	var envelope struct {
		Magic                              [6]byte
		Version                            uint32
		PublicKey                          []byte
		Namespace, Reserved, HashAlgorithm string
		Signature                          []byte
	}
	if err := ssh.Unmarshal(block.Bytes, &envelope); err != nil {
		return err
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(publicKey))
	if err != nil {
		return err
	}
	if string(envelope.Magic[:]) != "SSHSIG" || envelope.Version != 1 || envelope.Namespace != "containarium-ssh-key-registration" || envelope.HashAlgorithm != "sha512" || !bytes.Equal(pub.Marshal(), envelope.PublicKey) {
		return fmt.Errorf("wrong SSHSIG key or context")
	}
	hash := sha512.Sum512(nonce)
	data := ssh.Marshal(struct {
		Magic                              [6]byte
		Namespace, Reserved, HashAlgorithm string
		Hash                               []byte
	}{[6]byte{'S', 'S', 'H', 'S', 'I', 'G'}, envelope.Namespace, envelope.Reserved, envelope.HashAlgorithm, hash[:]})
	var sig ssh.Signature
	if err := ssh.Unmarshal(envelope.Signature, &sig); err != nil {
		return err
	}
	return pub.Verify(data, &sig)
}

func TestSSHRotate_HTTPFlow(t *testing.T) {
	for _, tc := range []struct {
		name                                string
		challengeStatus, registrationStatus int
		success                             bool
	}{
		{"success", 200, 200, true},
		{"signature rejected", 200, 400, false},
		{"challenge unimplemented", 501, 200, false},
		{"challenge absent", 404, 200, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := withSSHHome(t)
			oldPubPath, _, err := sshkey.Generate(sshkey.LocateOpts{HomeDir: home}, false)
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
			var challenges, registrations atomic.Int32
			var postedPublic atomic.Value
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer rotate-token" {
					t.Errorf("wrong method/auth: %s", r.Method)
				}
				switch r.URL.Path {
				case "/v1/user/ssh-keys:challenge":
					challenges.Add(1)
					w.WriteHeader(tc.challengeStatus)
					if tc.challengeStatus == 200 {
						fmt.Fprintf(w, `{"challenge_id":"challenge-1","nonce":%q}`, base64.StdEncoding.EncodeToString(nonce))
					}
				case "/v1/user/ssh-keys":
					registrations.Add(1)
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
					if err := verifyRotationProof(req.PublicKey, req.Signature, nonce); err != nil {
						t.Errorf("bad proof: %v", err)
					}
					postedPublic.Store(req.PublicKey)
					w.WriteHeader(tc.registrationStatus)
					if tc.registrationStatus == 200 {
						fp, _ := sshkey.Fingerprint(req.PublicKey)
						fmt.Fprintf(w, `{"key":{"name":"laptop","fingerprint":%q},"overlap_expires_at":"2026-10-20T00:00:00Z"}`, fp)
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
			if (err == nil) != tc.success {
				t.Fatalf("error=%v, success=%v", err, tc.success)
			}
			after, readErr := os.ReadFile(configPath)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if tc.success {
				if string(after) == g.Content || strings.Contains(string(after), "IdentityFile "+oldPath+"\n") || !strings.Contains(out.String(), "2026-10-20T00:00:00Z") {
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
			} else if registrations.Load() != 1 {
				t.Fatal("registration not submitted once")
			}
		})
	}
}
