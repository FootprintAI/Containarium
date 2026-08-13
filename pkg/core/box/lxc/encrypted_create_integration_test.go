//go:build incus

package lxc

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/testsupport/incusenv"
	"github.com/footprintai/containarium/pkg/core/box"
	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/zfscrypt"
	"github.com/footprintai/containarium/pkg/core/zfskey"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// The two questions #1199 could not answer without an Incus (#1332).
//
// #1199's remaining step — calling PreCreate from the create path — rests on
// two premises that were taken from documentation rather than from a running
// system, and the issue's own history says so: the assignee declined three
// times to write the wiring blind, citing a previous pair of PRs here that
// shipped code against a type no caller could produce. That was the right
// call, and these tests are the way to stop guessing.
//
// Premise 1: the daemon can name the dataset a container will live on.
// Premise 2: Incus will build an instance ON a dataset that already exists
//            (design §3, hook row 1: "tells Incus to use that pre-existing
//            dataset (Incus's 'instance from an existing zvol' path)").
//
// Premise 2 is the load-bearing one. If it does not hold, #1199 is not a
// wiring task at all and the design needs revisiting — which is a finding
// worth having as a red CI run rather than as a fourth sprint of "blocked".

// newTestKey returns 32 random bytes as a key. Synthetic, per-run, and never
// written anywhere but the throwaway pool on the runner.
func newTestKey(t *testing.T) zfskey.Key {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("generate key: %v", err)
	}
	key, err := zfskey.NewKey(b)
	if err != nil {
		t.Fatalf("wrap key: %v", err)
	}
	return key
}

// TestIntegrationIncus_ContainerDatasetNamesTheRealDataset checks premise 1
// against a container Incus actually created.
//
// This is the production resolver — incus.ContainerDataset, which #1259
// extracted from the quota-headroom path precisely so per-tenant encryption
// could use it. It has always been exercised on hosts whose pool was
// provisioned one particular way; a CI pool is provisioned by the daemon's
// own EnsureStorage, so this is the first time the two are compared.
//
// It matters because encryptionHooks.datasetResolver has to return this
// string BEFORE the instance exists. A resolver that is off by one level
// would create the encrypted dataset somewhere harmless, let Incus create an
// ordinary unencrypted one, and report a successful encrypted create.
func TestIntegrationIncus_ContainerDatasetNamesTheRealDataset(t *testing.T) {
	client := incusenv.Require(t)
	if err := client.InitializeInfrastructure(incus.DefaultNetworkConfig()); err != nil {
		t.Fatalf("the daemon's own infrastructure init failed: %v", err)
	}

	name := fmt.Sprintf("dsr%d", os.Getpid())
	instance := name + "-container"
	t.Cleanup(func() { incusenv.DeleteInstance(t, instance) })

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	defer cancel()

	if _, err := New(container.NewWithBackend(client)).Create(ctx, box.BoxSpec{
		Ref:       box.BoxRef{Tenant: name},
		Image:     "images:ubuntu/24.04",
		OSType:    pb.OSType_OS_TYPE_UBUNTU_2404,
		AutoStart: true,
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	actual := incusenv.DatasetFor(t, instance)
	if actual == "" {
		t.Fatalf("instance %s has no ZFS dataset", instance)
	}

	resolved, err := client.ContainerDataset(instance, "")
	if err != nil {
		t.Fatalf("ContainerDataset(%s): %v", instance, err)
	}
	if resolved != actual {
		t.Errorf("ContainerDataset(%s) = %q, but Incus put the instance on %q.\n"+
			"The daemon cannot name the dataset it is about to encrypt, so #1199's PreCreate "+
			"would encrypt a dataset nothing uses while Incus creates an ordinary one alongside it — "+
			"an encrypted create that reports success and delivers plaintext.",
			instance, resolved, actual)
	}
}

// TestIntegrationIncus_InstanceOnAPreExistingEncryptedDataset is premise 2,
// and the whole of what #1199 has been blocked on.
//
// The design's pre-create hook says: make the dataset with encryption=on,
// then tell Incus to use it. Nobody in the issue's history could run that.
// So: pre-create the dataset at exactly the path the daemon resolves, with
// the production CreateEncrypted, then drive the daemon's own create and see
// what Incus does with it.
//
// A failure here is not a broken test — it is the answer, and it says the
// remaining work on #1199 is a design question rather than a wiring task.
func TestIntegrationIncus_InstanceOnAPreExistingEncryptedDataset(t *testing.T) {
	client := incusenv.Require(t)
	if err := client.InitializeInfrastructure(incus.DefaultNetworkConfig()); err != nil {
		t.Fatalf("the daemon's own infrastructure init failed: %v", err)
	}

	zfs := zfscrypt.NewManager(zfscrypt.ExecRunner{})
	name := fmt.Sprintf("enc%d", os.Getpid())
	instance := name + "-container"

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	defer cancel()

	dataset, err := client.ContainerDataset(instance, "")
	if err != nil {
		t.Fatalf("ContainerDataset(%s): %v", instance, err)
	}
	t.Logf("pre-creating encrypted dataset %s for instance %s", dataset, instance)

	t.Cleanup(func() {
		incusenv.DeleteInstance(t, instance)
		// After the instance is gone the dataset may survive (if Incus never
		// adopted it) or not (if it did). Either way, leave nothing behind.
		_ = zfs.Destroy(context.Background(), dataset)
	})

	// This is PreCreate's ZFS half, running the production code path.
	if err := zfs.CreateEncrypted(ctx, dataset, newTestKey(t)); err != nil {
		t.Fatalf("could not pre-create the encrypted dataset %s: %v", dataset, err)
	}
	root, err := zfs.EncryptionRoot(ctx, dataset)
	if err != nil {
		t.Fatalf("read encryptionroot of %s: %v", dataset, err)
	}
	if root != dataset {
		t.Fatalf("pre-created %s but its encryptionroot is %q — it is not its own root", dataset, root)
	}

	// Now the daemon's own create, onto a dataset that already exists.
	_, createErr := New(container.NewWithBackend(client)).Create(ctx, box.BoxSpec{
		Ref:       box.BoxRef{Tenant: name},
		Image:     "images:ubuntu/24.04",
		OSType:    pb.OSType_OS_TYPE_UBUNTU_2404,
		AutoStart: true,
	})
	if createErr != nil {
		t.Fatalf("Incus will not build an instance on a pre-existing dataset: %v\n\n"+
			"This is design §3 hook row 1's premise — 'tells Incus to use that pre-existing dataset "+
			"(Incus's instance from an existing zvol path)' — and it does not hold as written. "+
			"#1199's remaining step is therefore not a wiring task; see the issue comment for the "+
			"alternatives this leaves open.", createErr)
	}

	// It succeeded. Now the part that decides whether it succeeded for the
	// right reason: Incus must have ADOPTED the encrypted dataset, not
	// created its own alongside it. A create that quietly lands on a
	// different, unencrypted dataset is the exact failure #1294 refuses to
	// ship — success reported, plaintext delivered.
	landed := incusenv.DatasetFor(t, instance)
	if landed != dataset {
		t.Fatalf("the create succeeded but the instance is on %q, not the encrypted dataset %q "+
			"that was pre-created for it — Incus ignored it rather than adopting it, so the "+
			"container is unencrypted while every daemon-side signal says otherwise", landed, dataset)
	}
	gotRoot, err := zfs.EncryptionRoot(ctx, landed)
	if err != nil {
		t.Fatalf("read encryptionroot of %s after the create: %v", landed, err)
	}
	if gotRoot != dataset {
		t.Fatalf("instance dataset %s has encryptionroot %q, want %q", landed, gotRoot, dataset)
	}
	t.Logf("Incus adopted the pre-existing encrypted dataset; instance %s is under encryptionroot %s",
		instance, gotRoot)
}
