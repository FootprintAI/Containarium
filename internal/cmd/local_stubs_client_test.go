//go:build containarium_client

package cmd

import (
	"errors"
	"os"
	"testing"
)

// TestHybridCommands_NoServer_NeverReachRealLocalMode is #1775's Done-when
// table-driven test: with no --server (and no CONTAINARIUM_SERVER/
// credentials.json fallback in play), every one of the thirteen hybrid
// commands (#1785 added collaborator) must error via a *Local stub — never
// via a working local-Incus call, because under containarium_client every
// *Local symbol IS one of
// those stubs (local_stubs_client.go). errors.Is against errNoLocalMode is
// exactly the assertion that proves this: it can only be true if the
// call reached a stub, since errNoLocalMode is not constructible any other
// way in this build.
func TestHybridCommands_NoServer_NeverReachRealLocalMode(t *testing.T) {
	// isCloudTarget (used by `info`) reads $HOME/.containarium/credentials.json
	// to resolve default_server's cached access model. Redirect HOME to an
	// empty temp dir so this test is hermetic — it must not depend on (or be
	// broken by) whoever is actually logged in on the machine running it.
	t.Setenv("HOME", t.TempDir())

	tests := []struct {
		name  string
		setup func()
		run   func() error
	}{
		{
			name: "create",
			setup: func() {
				noSSHKey = true // skip --ssh-key file I/O; the point here is reaching createLocal, not key handling
				forceRecreate = false
				createEncrypted = false
				createTenantID = ""
				createPool = ""
				createBackendID = ""
				createWait = false
			},
			run: func() error { return runCreate(testCmd(), []string{"testuser"}) },
		},
		{
			name:  "delete",
			setup: func() { forceDelete = false },
			run:   func() error { return runDelete(testCmd(), []string{"testuser"}) },
		},
		{
			name:  "get",
			setup: func() { containerGetFormat = "table" },
			run:   func() error { return runGet(testCmd(), []string{"testuser"}) },
		},
		{
			name:  "list",
			setup: func() { outputFormat = "table"; filterState = "all"; groupByLabel = "" },
			run:   func() error { return runList(testCmd(), nil) },
		},
		{
			name:  "info (system)",
			setup: func() {},
			run:   func() error { return runInfo(testCmd(), nil) },
		},
		{
			name:  "info (container)",
			setup: func() {},
			run:   func() error { return runInfo(testCmd(), []string{"testuser"}) },
		},
		{
			name:  "label list",
			setup: func() { labelListFormat = "table" },
			run:   func() error { return runLabelList(testCmd(), []string{"testuser"}) },
		},
		{
			name:  "label set",
			setup: func() { labelOverwrite = true },
			run:   func() error { return runLabelSet(testCmd(), []string{"testuser", "k=v"}) },
		},
		{
			name:  "label remove",
			setup: func() {},
			run:   func() error { return runLabelRemove(testCmd(), []string{"testuser", "k"}) },
		},
		{
			name:  "install-stack",
			setup: func() {},
			run:   func() error { return runInstallStack(testCmd(), []string{"testuser", "nodejs"}) },
		},
		{
			name: "resize",
			setup: func() {
				newCPU, newMemory, newDisk, newCPURequest, newMemoryRequest = "4", "", "", "", ""
			},
			run: func() error { return runResize(testCmd(), []string{"testuser"}) },
		},
		{
			name:  "ssh-config sync",
			setup: func() { sshConfigOutPath = t.TempDir() + "/ssh_config"; sshConfigForce = true },
			run:   func() error { return runSSHConfigSync(testCmd(), nil) },
		},
		{
			name: "collaborator add",
			setup: func() {
				keyFile := t.TempDir() + "/bob.pub"
				if err := os.WriteFile(keyFile, []byte("ssh-ed25519 AAAAtest bob@example.com"), 0o600); err != nil {
					t.Fatalf("write test ssh key: %v", err)
				}
				collaboratorSSHKeyFiles = []string{keyFile}
				collaboratorGrantSudo = false
				collaboratorGrantRuntime = false
			},
			run: func() error { return runCollaboratorAdd(testCmd(), []string{"owner", "bob"}) },
		},
		{
			name:  "collaborator remove",
			setup: func() {},
			run:   func() error { return runCollaboratorRemove(testCmd(), []string{"owner", "bob"}) },
		},
		{
			name:  "collaborator list",
			setup: func() {},
			run:   func() error { return runCollaboratorList(testCmd(), []string{"owner"}) },
		},
		{
			name:  "prune",
			setup: func() { pruneState, pruneNameContains, pruneOlderThan, pruneLabels = "stopped", "", "", nil },
			run:   func() error { return runPrune(testCmd(), nil) },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Every hybrid dispatches on serverAddr/httpMode; pin both to the
			// "no server anywhere" case regardless of what an earlier subtest
			// (or -run reordering) left them at.
			serverAddr, httpMode, authToken = "", false, ""
			tt.setup()

			err := tt.run()
			if err == nil {
				t.Fatalf("expected an error with no server configured, got nil")
			}
			if !errors.Is(err, errNoLocalMode) {
				t.Errorf("expected errNoLocalMode (i.e. the call resolved to a *Local stub, not real Incus code), got: %v", err)
			}
		})
	}
}
