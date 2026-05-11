package mcp

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// generateEphemeralSSHKey creates an ed25519 keypair client-side and
// returns the OpenSSH-formatted public key (authorized_keys line) plus
// the OpenSSH PEM-encoded private key.
//
// Generating on the MCP client side rather than server-side means the
// private key never traverses the network — it stays on the operator's
// laptop where it was created. The daemon only ever sees the public key
// (via the standard ssh_keys field on CreateContainerRequest), so the
// rest of the platform doesn't need to know about ephemeral keys at all.
//
// Used by create_container when the caller doesn't pass ssh_keys: a
// fresh per-container keypair is generated, the public half goes into
// the container's authorized_keys, and the private half is returned to
// the agent with instructions to save it.
func generateEphemeralSSHKey(label string) (publicKeyAuthorizedKeys string, privateKeyPEM []byte, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", nil, fmt.Errorf("generate ed25519: %w", err)
	}

	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "", nil, fmt.Errorf("wrap public key: %w", err)
	}
	publicKeyAuthorizedKeys = string(ssh.MarshalAuthorizedKey(sshPub))

	// MarshalPrivateKey returns a *pem.Block. pem.EncodeToMemory turns
	// it into the file-on-disk form (`-----BEGIN OPENSSH PRIVATE KEY-----...`).
	pemBlock, err := ssh.MarshalPrivateKey(priv, label)
	if err != nil {
		return "", nil, fmt.Errorf("marshal private key: %w", err)
	}
	privateKeyPEM = pem.EncodeToMemory(pemBlock)

	return publicKeyAuthorizedKeys, privateKeyPEM, nil
}
