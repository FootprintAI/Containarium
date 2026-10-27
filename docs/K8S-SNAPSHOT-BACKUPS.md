# Kubernetes PVC snapshot backups

`containarium backup create <tenant> --box --dest snapshot` creates a CSI
`VolumeSnapshot` of the box's active data PVC. `backup list`, `backup get`
and `backup delete <id>` use the same backup index as archive backups.

Only the mounted `/home/agent/workspace` data volume is included. The image,
container writable layer, Secrets, memory and running processes are not captured.
This complements database dumps and Incus archive backups. Snapshot records have
no archive SHA-256 or archive byte size; their CSI identity is the snapshot UID.

## Requirements

- The box uses a bound PVC backed by a CSI StorageClass.
- The cluster has the v1 snapshot CRDs, snapshot controller and a CSI driver
  supporting snapshots.
- A VolumeSnapshotClass matches the source StorageClass's provisioner and has
  `deletionPolicy: Delete`. One matching class, or one matching default class,
  must be unambiguous. Retain classes are refused so deleting a backup does not
  deliberately retain its underlying storage snapshot.
- The daemon can get StorageClasses; get/list VolumeSnapshotClasses; and
  get/list/create/delete VolumeSnapshots in tenant namespaces. The Helm chart
  includes these permissions. No direct VolumeSnapshotContent writes are needed.

Missing APIs or a missing/ambiguous matching class are rejected before creating
any Kubernetes resource. Snapshot creation waits up to five minutes for
`status.readyToUse`; a failed or timed-out snapshot is deleted. Metadata is
written only after readiness. If writing metadata fails, the snapshot is cleaned
up too. Cleanup errors are reported instead of silently losing track of them.

## Restore

```sh
containarium backup create <tenant> --box --dest snapshot --server <host>
containarium backup list <tenant> --server <host>
containarium backup restore <snapshot-id> --server <host>
containarium backup delete <snapshot-id> --server <host>
```

Restore targets the existing source box in the source namespace. Cross-tenant
and cross-namespace restores are unsupported. Do not supply database, clean,
target, GCS or age/key flags for snapshot operations. Storage encryption is
controlled by the CSI provider and its StorageClass, not the archive age/KMS path.

Restore validates the snapshot UID and readiness, creates a uniquely named PVC
with the snapshot as its dataSource, suspends the Sandbox, waits for its old pod
to disappear, switches the data-volume claim in the Sandbox template, and resumes
the box. Success waits for a Ready pod actually mounting the restored PVC. This
also supports StorageClasses using WaitForFirstConsumer: the consumer is started
before waiting for readiness. Subsequent snapshots follow the active claim.

The old PVC is retained for recovery. If restore fails after suspension, the box
may remain suspended; inspect the Sandbox and retained PVCs before resuming or
retrying. New PVCs are retained on restore failure too, because an API timeout
can occur after a switch was committed. No existing PVC is deleted by restore.
Restore is serialized with snapshot creation within a daemon; use one active
writer daemon for a cluster. Other lifecycle operations must not edit the box
concurrently with restore. The box's current image and configuration are reused.

Snapshot deletion waits for the VolumeSnapshot object to disappear before
removing the index entry. The CSI controller owns underlying snapshot-content
cleanup. The namespace and backup index must remain available: namespace deletion
also deletes its snapshots, and loss of the daemon's backup index requires
separate recovery of that index. A CSI snapshot is storage-provider scoped; this
feature does not copy it to GCS or promise survival of storage-provider loss.

Running workloads are not quiesced during capture. This provides the consistency
of the CSI driver's point-in-time snapshot, not an application-coordinated
transaction-consistent database backup. Stop application writes when stronger
consistency is required, or use the existing logical backup path.

## Verification

Fake-client tests cover creation/listing/deletion, restored PVC dataSource,
retention of the old disk, subsequent snapshots of the restored disk, unsupported
clusters, failed/timeout cleanup, UID/namespace isolation and stopping before
switching storage. RPC, CLI and MCP tests cover option validation and requests.

Run the dedicated kind lane on a host with Docker access:

```sh
bash scripts/k8s-snapshot-e2e.sh
```

It creates a disposable cluster with agent-sandbox v1.0.8, external-snapshotter
v8.7.0 and CSI hostpath deployment files from v1.19.0. It writes a file, captures a
snapshot, deletes the file, restores, compares the content and deletes the
snapshot. The workflow `k8s-e2e.yml` includes this lane. It does not use or change
an ambient cluster. Hostpath is a test driver, not a production storage choice.
