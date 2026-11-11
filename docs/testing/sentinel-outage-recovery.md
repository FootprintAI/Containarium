# Sentinel backend outage recovery (#1139)

The local watchdog probe uses `sentinel-self-check.invalid`. The SNI router
closes this probe before tenant lookup or fallback dialing: reaching that
point proves the local mux, dispatch and SNI parser reacted. Backend health
remains the responsibility of the backend health checks. A stalled local
dispatch still reaches the watchdog's exit threshold.

CI runs `TestSelfCheck_BackendOutageDoesNotTriggerExit` (three routing cases),
`TestSelfCheck_UnservicedDispatchStillTriggersExit`, and
`TestBackendOutage_SameIPReregisterWithRotatedTLS`. The last test advances
the registration clock eight hours and reconnects to the same backend address
with a new TLS certificate. It simulates registration expiry; it does not
claim eight hours of live outage coverage. `TestSentinelOutageHarness` checks
the live runner against synthetic CLI services, including failed SSH/HTTPS
recovery, changed backend IP, and sentinel restart.

## Verify on dev

Run against the sprint's deployed commit during the batched verification
pass, or an isolated sentinel/backend pair. The runner stops the configured
GCE VM. Use a disposable backend carrying a synthetic SSH login and an HTTPS
endpoint with a unique, fixed response body. Keep its internal IP reserved.
Both application routes must lead through the sentinel to this backend;
use direct SSH management aliases for the sentinel and backend itself. The
backend alias must bypass application forwarding (a management jump host is
fine) and be able to run `curl` against its local daemon health endpoint.
SSH aliases must
already have credentials and pinned host keys; the runner uses batch mode
and strict host-key checking. It preserves HTTPS certificate verification.

Set these variables in the operator's environment (retain credentials there):

```bash
export GCP_PROJECT='<project>' GCP_ZONE='<zone>' BACKEND_VM='<disposable-vm>'
export SENTINEL_SSH_TARGET='<sentinel-management-ssh-alias>'
export BACKEND_SSH_TARGET='<backend-management-ssh-alias>'
export APP_SSH_TARGET='<synthetic-user-ssh-alias-through-sentinel>'
export SENTINEL_HTTPS_IP='<sentinel-address>'
export APP_URL='https://<synthetic-host>/outage-proof'
export EXPECTED_HTTPS_BODY='<unique-response-body>'
export KEYSYNC_INTERVAL_SECONDS=120 RECOVERY_SECONDS=30
bash scripts/ci/sentinel-outage-smoke.sh > outage-185s.log 2>&1
OUTAGE_SECONDS=14400 bash scripts/ci/sentinel-outage-smoke.sh > outage-4h.log 2>&1
```

Use the deployed keysync interval and re-registration recovery bound instead
of the example defaults when configured differently. The recovery timer
starts after the backend's local `/health` succeeds; boot has a separate
`BOOT_TIMEOUT_SECONDS` bound (default 300). Set `BACKEND_HEALTH_PORT` if its
daemon does not use 8080. The default outage is
185 seconds and must exceed the keysync interval. Run the long pass beyond
any additional connection/key lifetime configured by the fixture. For a
re-key pass, provision the disposable backend to rotate its synthetic login
key and application TLS leaf during boot, and configure the SSH alias with
both synthetic login keys (the first works before boot, the replacement
after boot). Verify separately, using an alias that offers only the old key,
that the old key is rejected after recovery.

The runner checks initial SSH/HTTPS success, that both fail while stopped,
the same internal IP on return, and both protocols recovering within the
configured bound. It checks sentinel PID, start timestamp and systemd restart
count throughout; automatic systemd recovery also fails this test. A failed
assertion during the outage attempts to start the backend before exiting.
Retain the deployed commit, duration, runner output, sentinel logs and
key/certificate fingerprints in the pass's evidence; sanitize deployment
details before posting to a public issue. A runner self-test or merged PR
does not mark the sprint verification row complete.
