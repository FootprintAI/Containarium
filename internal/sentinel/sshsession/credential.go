package sshsession

import (
	"fmt"

	"golang.org/x/crypto/ssh"
)

// ExtractCredential parses the raw wire-format public key bytes sshpiperd
// hands a plugin's PublicKeyAuth callback (ssh.PublicKey.Marshal() output —
// see libplugin.SshPiperPluginConfig.PublicKeyCallback) and derives the
// credential handle to record.
//
//   - A certificate (ssh.Certificate, CertType == ssh.UserCert) yields
//     AuthMethodCertificate with KeyID, Serial, and the fingerprint of the
//     signing CA's public key — the trio containarium#1980 requires,
//     since under TrustedUserCAKeys the login name alone only identifies
//     the target account.
//   - Anything else that parses as a public key yields AuthMethodPublicKey
//     with just that key's own fingerprint.
//
// It never returns the raw key bytes themselves — only derived,
// non-secret identifiers — and a parse failure is reported as an error,
// never as a reason to reject the connection: see plugin.go's
// publicKeyCallback, which always defers to the next plugin regardless of
// this function's outcome.
func ExtractCredential(rawPublicKey []byte) (AuthMethod, Credential, error) {
	pub, err := ssh.ParsePublicKey(rawPublicKey)
	if err != nil {
		return AuthMethodUnknown, Credential{}, fmt.Errorf("parse offered public key: %w", err)
	}

	if cert, ok := pub.(*ssh.Certificate); ok && cert.CertType == ssh.UserCert {
		return AuthMethodCertificate, Credential{
			KeyID:          cert.KeyId,
			Serial:         cert.Serial,
			CAFingerprint:  ssh.FingerprintSHA256(cert.SignatureKey),
			KeyFingerprint: ssh.FingerprintSHA256(cert.Key),
		}, nil
	}

	return AuthMethodPublicKey, Credential{
		KeyFingerprint: ssh.FingerprintSHA256(pub),
	}, nil
}
