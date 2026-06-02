# `containarium` Terraform module

Provisions a Containarium deployment on GCP (spot daemon + optional sentinel
HA front). Consume by `?ref=`-pinning a tag:

```hcl
module "containarium" {
  source = "git::https://github.com/FootprintAI/Containarium//terraform/modules/containarium?ref=v0.21.0"
  # ...
}
```

Requires **Terraform >= 1.2** (for the `sentinel_auth_secret` precondition).

---

## Migration: `0.9.x` → `0.21.x`

This is a **breaking variable-API change**. A consumer pinned at `0.9.1` that
bumps `?ref=` to `v0.21.0` will fail `terraform plan` with `Unsupported
argument` until the removed variables below are deleted from the module block.
(Var count: 37 → 44.)

### Removed variables

| Removed | Why |
|---|---|
| `enable_glb_backend` | **GLB dropped** (`077c84b`). The GCP Global Load Balancer (~$648/mo) was replaced by **Caddy TLS termination**. |
| `enable_health_check_firewall` | Belonged to the GLB health-check path, removed with the GLB. |

**This removal is intentional.** External HTTPS now flows
**sentinel DNAT → Caddy → Let's Encrypt (HTTP-01 ACME)** instead of through a
Google-managed HTTPS load balancer.

**How the daemon is fronted now:** the daemon's REST (`:8080`) and gRPC
(`:50051`) ports are **no longer exposed externally** — they were removed from
the sentinel DNAT forwarded-ports default. Reach the daemon through **Caddy on
`:443`** (which terminates TLS and reverse-proxies). If you were fronting `:8080`
with the GLB, that path is gone; use the Caddy/`:443` ingress.

To migrate a GLB-less consumer (the common case): **just delete** the
`enable_glb_backend` / `enable_health_check_firewall` lines — there is no
replacement variable to set.

### Added variables (`v0.21.0`)

| Variable | Default | Notes |
|---|---|---|
| `base_domain` | set | Apex for Caddy-managed certs / routing. |
| `enable_app_hosting` | `false` | Caddy app-hosting / public route management. |
| `enable_proxy_protocol` | `false` | Prepend PROXY v2 so Caddy sees the real client IP. |
| `proxy_protocol_trusted_cidrs` | defaulted | Trusted sources for the PROXY header. |
| `allowed_management_sources` | defaulted | CIDRs allowed to reach management/SSH. |
| `sentinel_auth_secret` | `""` | **Sentinel↔daemon HMAC secret (32+ bytes).** See below. |
| `enable_peer_mtls` | `false` | Phase 0.5 peer mTLS. **Requires `sentinel_auth_secret`.** |
| `kms_key_self_link` | `""` | KMS key for encryption integrations. |
| `zfs_encryption_keyfile` | `""` | Per-host ZFS encryption keyfile path. |

### Required variables

**None of the new variables are Terraform-required** — all have defaults, so
omitting them will not error `plan`. Two need a closer read:

- **`sentinel_auth_secret`** defaults to `""`, which means *"fall back to
  pre-Phase-0 behavior with the audit-known vulnerabilities."* It is **not**
  enforced by Terraform, but you **should set it** (32+ bytes, the same value on
  the sentinel and every daemon it talks to) whenever `enable_sentinel = true`.
  An empty/short secret is exactly the path into the silent keysync/certsync
  **401 lockout** tracked in [#341]: both daemons report `active`, but every
  sync fails until the secret is configured.

- **`enable_peer_mtls = true` now requires `sentinel_auth_secret`** to be 32+
  bytes — enforced by a `precondition`, so a mismatch fails at **plan time**
  with a clear message instead of coming up broken. (This is why the module now
  requires Terraform >= 1.2.)

[#341]: https://github.com/FootprintAI/Containarium/issues/341

## Upgrading the daemon (`containarium_version`)

The startup script reconciles the installed binary to `containarium_version`
on **every boot**: it compares `containarium version` against the requested
value (substring match) and only re-downloads + `systemctl restart
containarium` when they differ. So bumping the version *does* upgrade the
daemon — with two caveats that bit a prod sentinel-HA deployment ([#385]):

- **A metadata-only `terraform apply` does not restart the instance.** The new
  `startup-script` lands in instance metadata but only runs on the next boot.
  To upgrade an existing VM either reboot it, let a preemption-recovery cycle
  it, or force a replacement:

  ```sh
  # workhorse (spot VM); use ...sentinel[0] for the sentinel
  terraform apply -replace='module.containarium.google_compute_instance.jump_server_spot[0]'
  ```

- **Sentinel-HA recovery can't silently downgrade anymore.** A recovered
  workhorse pulls from the sentinel's `:8888` binary server first, but now
  **declines** a sentinel-served binary whose version doesn't match
  `containarium_version`, falling back to `containarium_binary_url` (the
  authoritative source for a pinned version). Still, **upgrade the sentinel
  first** so its `:8888` server hands out the matching version and the
  workhorse can take the fast same-version path on recovery.

  > The sentinel's own binary is still existence-aware on its boot path;
  > applying the same version-aware reconcile to `startup-sentinel.sh` is a
  > tracked follow-up. Until then, upgrade the sentinel via `-replace` (or the
  > out-of-band swap below) so it serves the intended version.

**Out-of-band swap** (when you can't reboot, e.g. a live upgrade): on the
**sentinel first**, then the workhorse — `curl` the release binary to
`/usr/local/bin/containarium.new`, `chmod +x`, verify `.new version`, atomic
`mv` over `/usr/local/bin/containarium`, then `systemctl restart containarium`
(workhorse) / `containarium-sentinel` (sentinel). The sentinel's admin sshd is
on **port 2222** (22 is sshpiper), and restarting the sentinel briefly serves a
self-signed cert on the public `:443`.

[#385]: https://github.com/FootprintAI/Containarium/issues/385
