package sshkey

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestSignChallenge_CloudProofContract(t *testing.T) {
	for _, keyType := range []string{ssh.KeyAlgoED25519, ssh.KeyAlgoRSA} {
		t.Run(keyType, func(t *testing.T) {
			var privateKey any
			var err error
			if keyType == ssh.KeyAlgoRSA {
				privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
			} else {
				_, privateKey, err = ed25519.GenerateKey(rand.Reader)
			}
			if err != nil {
				t.Fatal(err)
			}
			signer, err := ssh.NewSignerFromKey(privateKey)
			if err != nil {
				t.Fatal(err)
			}
			block, err := ssh.MarshalPrivateKey(privateKey, "proof-test")
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "key")
			if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
				t.Fatal(err)
			}
			nonce := []byte{0, 255, 42, 17, 128, 1, 9, 10}
			proof, err := SignChallenge(path, nonce)
			if err != nil {
				t.Fatal(err)
			}
			var sig ssh.Signature
			if err := ssh.Unmarshal([]byte(proof), &sig); err != nil {
				t.Fatalf("proof must be an RFC 4253 signature blob: %v", err)
			}
			if keyType == ssh.KeyAlgoRSA && sig.Format != ssh.KeyAlgoRSASHA256 && sig.Format != ssh.KeyAlgoRSASHA512 {
				t.Fatalf("cloud requires an RSA SHA-2 signature, got %q", sig.Format)
			}
			message := append([]byte("containarium-ssh-key-proof-v1\x00"), nonce...)
			if err := signer.PublicKey().Verify(message, &sig); err != nil {
				t.Fatalf("proof does not sign the cloud's exact message bytes: %v", err)
			}
			for name, wrong := range map[string][]byte{
				"nonce only":   nonce,
				"no separator": append([]byte("containarium-ssh-key-proof-v1"), nonce...),
				"base64 nonce": []byte("containarium-ssh-key-proof-v1\x00" + base64.StdEncoding.EncodeToString(nonce)),
				"hex nonce":    []byte("containarium-ssh-key-proof-v1\x00" + hex.EncodeToString(nonce)),
			} {
				if err := signer.PublicKey().Verify(wrong, &sig); err == nil {
					t.Errorf("proof also verified for %s", name)
				}
			}
		})
	}
}
