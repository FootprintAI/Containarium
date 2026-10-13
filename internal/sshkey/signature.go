package sshkey

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/pem"
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"
)

// RegistrationNamespace is the application namespace proposed on #2523.
const RegistrationNamespace = "containarium-ssh-key-registration"

// SignChallenge emits OpenSSH PROTOCOL.sshsig version 1 armor. The input is
// the decoded nonce, not the HTTP Base64 string. Private key bytes stay local.
func SignChallenge(privatePath string, nonce []byte) (string, error) {
	if len(nonce) == 0 {
		return "", fmt.Errorf("empty SSH key challenge")
	}
	key, err := os.ReadFile(privatePath)
	if err != nil {
		return "", err
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("parse signing key: %w", err)
	}
	magic := [6]byte{'S', 'S', 'H', 'S', 'I', 'G'}
	hash := sha512.Sum512(nonce)
	data := ssh.Marshal(struct {
		Magic                              [6]byte
		Namespace, Reserved, HashAlgorithm string
		Hash                               []byte
	}{magic, RegistrationNamespace, "", "sha512", hash[:]})
	sig, err := signer.Sign(rand.Reader, data)
	if err != nil {
		return "", fmt.Errorf("sign challenge: %w", err)
	}
	blob := ssh.Marshal(struct {
		Magic                              [6]byte
		Version                            uint32
		PublicKey                          []byte
		Namespace, Reserved, HashAlgorithm string
		Signature                          []byte
	}{magic, 1, signer.PublicKey().Marshal(), RegistrationNamespace, "", "sha512", ssh.Marshal(sig)})
	return string(pem.EncodeToMemory(&pem.Block{Type: "SSH SIGNATURE", Bytes: blob})), nil
}
