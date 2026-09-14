package server

import (
	"context"
	"errors"
	"testing"

	"github.com/footprintai/containarium/internal/secrets"
)

// fakeSecretsReader is a minimal secretsReader for unit tests — no real
// Postgres or KMS backend, per #1836 (resolving a tenant's self-registered
// backup recipient must be testable in isolation).
type fakeSecretsReader struct {
	values map[string]string // "username/name" -> value
	err    error
}

func (f *fakeSecretsReader) Get(_ context.Context, username, name string) (*secrets.SecretMetadata, string, error) {
	if f.err != nil {
		return nil, "", f.err
	}
	v, ok := f.values[username+"/"+name]
	if !ok {
		return nil, "", secrets.ErrNotFound
	}
	return &secrets.SecretMetadata{Username: username, Name: name}, v, nil
}

func TestResolveAgeRecipient_ExplicitAlwaysWins(t *testing.T) {
	store := &fakeSecretsReader{values: map[string]string{
		"alice/" + backupAgeRecipientSecretName: "age1registered",
	}}
	got, err := resolveAgeRecipient(context.Background(), store, "alice", "age1explicit")
	if err != nil {
		t.Fatal(err)
	}
	if got != "age1explicit" {
		t.Errorf("got %q, want the explicit request value to win over the registered secret", got)
	}
}

func TestResolveAgeRecipient_FallsBackToRegisteredSecret(t *testing.T) {
	store := &fakeSecretsReader{values: map[string]string{
		"alice/" + backupAgeRecipientSecretName: "age1registered",
	}}
	got, err := resolveAgeRecipient(context.Background(), store, "alice", "")
	if err != nil {
		t.Fatal(err)
	}
	if got != "age1registered" {
		t.Errorf("got %q, want the tenant's registered secret", got)
	}
}

func TestResolveAgeRecipient_NoSecretNoFlagIsPlaintextUnchanged(t *testing.T) {
	store := &fakeSecretsReader{values: map[string]string{}}
	got, err := resolveAgeRecipient(context.Background(), store, "alice", "")
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Errorf("got %q, want empty (plaintext) when neither a flag nor a secret is set", got)
	}
}

func TestResolveAgeRecipient_NilStoreIsPlaintextUnchanged(t *testing.T) {
	// A standalone daemon (no Postgres/secrets store configured) must not
	// error or panic on a plain `backup create` with no --age-recipient.
	got, err := resolveAgeRecipient(context.Background(), nil, "alice", "")
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Errorf("got %q, want empty on a standalone daemon", got)
	}
}

func TestResolveAgeRecipient_OtherStoreErrorsPropagate(t *testing.T) {
	store := &fakeSecretsReader{err: errors.New("boom: kms unavailable")}
	_, err := resolveAgeRecipient(context.Background(), store, "alice", "")
	if err == nil {
		t.Fatal("expected a real store error (not ErrNotFound) to propagate rather than silently fall back to plaintext")
	}
}

// backupSecretsReader must convert a nil *secrets.Store field into a TRUE
// nil interface. Wrapping a nil concrete pointer directly in the
// secretsReader interface produces a non-nil interface holding a nil
// pointer — resolveAgeRecipient's `store == nil` check would then miss it,
// and calling Get on it would nil-deref-panic every plaintext backup on a
// standalone daemon (#1836).
func TestBackupSecretsReader_NilStoreIsTrulyNilInterface(t *testing.T) {
	cs := &ContainerServer{}
	r := backupSecretsReader(cs)
	if r != nil {
		t.Fatalf("expected a true nil interface for a standalone daemon (no secrets store configured), got a non-nil interface wrapping %#v", r)
	}
}
