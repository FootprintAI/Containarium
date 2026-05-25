# Secrets — operator runbook

**Related:**
- [`docs/SECRETS-MANAGEMENT-DESIGN.md`](SECRETS-MANAGEMENT-DESIGN.md) — the architecture (read first if unfamiliar).
- [`docs/DISASTER-RECOVERY.md`](DISASTER-RECOVERY.md) — broader recovery scenarios this fits into.
- [`docs/SECURITY-ENCRYPTION-AT-REST.md`](SECURITY-ENCRYPTION-AT-REST.md) — the overall at-rest posture this is part of.

This doc is the operator's manual for the **master encryption key** that protects every tenant secret. The file is `/etc/containarium/secrets.key` on the daemon host (32 bytes, mode `0400`, root-owned). The daemon auto-generates it on first start; losing it makes every stored secret unrecoverable ciphertext.

> **Why this matters.** The daemon encrypts each tenant secret with AES-256-GCM using this key. The ciphertext lives in `containarium-core-postgres`. Without the key, those rows are bytes. With the key, they're plaintext to anyone who can decrypt — so back it up off-host and protect access.

## Back up the keyfile off-host

### GCP Secret Manager (recommended for cloud deployments)

The pattern we use in production. Same project as the daemon VM; relies on project-admin IAM for access (no new permissions surface). The keyfile bytes pipe directly from disk into Secret Manager — they never traverse stdout or this transcript.

Run **on the daemon host**:

```bash
# One-time: create the secret resource.
sudo gcloud secrets create containarium-prod-secrets-master \
  --project=<your-gcp-project> \
  --replication-policy=automatic

# Upload the current keyfile as version 1.
sudo gcloud secrets versions add containarium-prod-secrets-master \
  --project=<your-gcp-project> \
  --data-file=/etc/containarium/secrets.key

# Verify (metadata only — does not print bytes).
sudo gcloud secrets versions list containarium-prod-secrets-master \
  --project=<your-gcp-project> \
  --limit=3 \
  --format='table(name,state,createTime)'
```

After each future rotation (see "Rotation" below), repeat the `versions add` step. The old version remains accessible via `gcloud secrets versions access N` until you explicitly destroy it — useful if a rotation goes wrong and you need to roll back.

### Self-hosters / non-GCP

The keyfile is just 32 bytes. Any off-host secure store works:

- **HashiCorp Vault**: `vault kv put containarium/secrets-master value=@/etc/containarium/secrets.key`.
- **Password manager** (1Password, Bitwarden): paste the base64 of the file (`base64 /etc/containarium/secrets.key`) into a secure note.
- **Encrypted USB / printout in a safe**: not joking — for single-tenant self-hosters this can be enough.

The rule: the backup must be reachable when the daemon host is unreachable. A copy on the same VM is **not** a backup.

## Restore — daemon host lost the keyfile

Symptom: the daemon refuses to start, or `containarium secrets get <user> <name>` returns "ciphertext authentication failed".

Steps (GCP Secret Manager backup):

```bash
# Pull the most recent version of the keyfile back to disk.
gcloud secrets versions access latest \
  --secret=containarium-prod-secrets-master \
  --project=<your-gcp-project> \
  | sudo tee /etc/containarium/secrets.key >/dev/null

# Restore the file mode and ownership.
sudo chmod 0400 /etc/containarium/secrets.key
sudo chown root:root /etc/containarium/secrets.key

# Restart the daemon — it'll load the key at startup.
sudo systemctl restart containarium.service

# Verify the secrets store came up cleanly.
sudo journalctl -u containarium.service --since '60 sec ago' --no-pager \
  | grep -E 'secrets|master key'
```

You should see:

```
... Secrets store ready (file-keyed, AES-256-GCM)
```

If you instead see `Failed to load secrets master key` or the daemon refuses to start, the restored bytes don't match what was originally written. Cross-check the Secret Manager version (`versions list`) and try an earlier one.

## Rotation

The daemon doesn't ship an automated rotation command in v1 (see `SECRETS-MANAGEMENT-DESIGN.md` non-goals). Manual rotation looks like this:

1. Generate a new key: `sudo dd if=/dev/urandom of=/tmp/secrets.key.new bs=32 count=1 status=none && sudo chmod 0400 /tmp/secrets.key.new`.
2. **Re-encrypt every existing secret** under the new key. There's no built-in command for this — you'd need a small migration script that reads each secret with the old key, encrypts with the new, and writes back. Until that ships, rotation means accepting that all previously-stored secrets become unrecoverable.
3. Swap: `sudo mv /tmp/secrets.key.new /etc/containarium/secrets.key`.
4. `sudo systemctl restart containarium.service`.
5. Upload the new key to Secret Manager: `gcloud secrets versions add ...` (see backup section above).

**For now**: treat rotation as a "destroy everything and start fresh" operation. If you actually need rotation in production, file an issue and we'll prioritize the migration tooling.

## Threat model — what backup protects against

| Failure | Recovers from backup? |
|---|---|
| Daemon VM disk corruption / accidental `rm /etc/containarium/secrets.key` | Yes |
| Daemon VM deleted (lost the boot disk) | Yes — restore on a fresh VM |
| GCP project deleted | No — back up cross-project too if this is a real concern |
| Operator compromise (someone with project-admin reads the secret) | No (and the on-disk file would be readable too) |
| Postgres corruption / data loss | Partial — keyfile is fine, but ciphertext is gone; restore Postgres first |
| Ciphertext tampering | The GCM auth tag catches it; data is unrecoverable, no key issue |

## Quick reference

- **Keyfile path on the daemon host**: `/etc/containarium/secrets.key`
- **File mode**: `0400`, root-owned
- **File size**: exactly 32 bytes (256-bit AES key)
- **Auto-generated**: yes, on first daemon start if missing
- **In our prod**: backed up at `projects/<your-gcp-project>/secrets/containarium-prod-secrets-master/versions/1` as of 2026-05-17
- **Encryption**: AES-256-GCM with `(username, name)` as AAD per `SECRETS-MANAGEMENT-DESIGN.md` §4
- **Storage of ciphertext**: `secrets` table in `containarium-core-postgres`
