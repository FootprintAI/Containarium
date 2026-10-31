# Daemon Postgres degraded-start verification

This drill covers #3044 and #3130 on one deployed commit. Run it on a
disposable backend with working control-plane enrollment and a tunnel,
where stopping Postgres and restarting the daemon are permitted. Record
the deployed commit, daemon version, start time, and endpoint responses.
The tests below do not replace this deployed control-plane verification.

## Automated regression coverage

```bash
go test -race -count=1 ./internal/gateway ./internal/cmd ./internal/server \
  -run 'TestHealthEndpoint_|TestStartupListener_|TestGatewayStart_|TestStartupHealth_|TestBindStartupHealth|TestWaitForPostgres_|TestPostgresStartupGate_|TestNetworkPolicy_Degraded|TestNetworkPolicy_InstallDurableStore|TestRecoveryWatcher_|TestNewPostgresRecoveryWatcher_|TestDualServer_RecoveryWatcher|TestStoreRecovery_|TestSecretsRecovery_'
```

The startup tests hold the wait for core services and use an unreachable
Postgres connection; `/health` must answer degraded within three seconds.
The gateway tests exercise the early listener's handover to the real mux
and verify that a failed core Postgres readiness entry still reports
degraded. The network-policy tests prove that rejected operator writes
change nothing, reads remain available, and in-process enforcement writers
remain active on the fallback. Recovery-watcher tests cover the opt-in
restart's consecutive-success and minimum-uptime requirements. The
store-recovery tests (#3326) use a fake Postgres that is down and then up:
a registered family turns from `NOT_SERVING` to `SERVING` with no restart,
two families share one pool and one dial per attempt, and the self-restart
watcher holds while a family is pending. The secrets-recovery tests (#3327)
apply that to the tenant secrets store: its RPCs answer `UNAVAILABLE` and
`containarium.secrets` is `NOT_SERVING` while Postgres is down, the store
installs once it answers, and `CONTAINARIUM_REQUIRE_ENVELOPE` without a KMS
backend refuses the late install. The set/get round trip runs only with
`CONTAINARIUM_TEST_DSN` set (the store-integration lane).

## Deployed outage drill

1. Confirm the disposable host is not in use by another verification pass.
   Record the commit from its deployment record and the daemon version from
   `/health`. Confirm the Postgres connection string is configured even
   while its core container is stopped; an intentionally memory-only
   deployment does not exercise the fallback gate.
2. Record a baseline HTTP 200 `status: healthy` at `/health` and HTTP 200
   `status: SERVING` at
   `/v1/health?service=containarium.core_postgres`. Confirm the control
   plane lists the backend as connected. Record an existing network policy
   that can be read after the restart, and use a separate synthetic policy
   name for the mutation probe.
3. Stop the host's core Postgres container with
   `incus stop <core-postgres-container>` and restart the daemon with
   `sudo systemctl restart containarium`. Immediately poll
   `http://localhost:<http-port>/health` once per second. Record elapsed
   time to the first HTTP response. Within a few seconds of startup, expect
   HTTP 200, `status: degraded` and a reason identifying the startup wait.
   During the waits, `/v1/containers` must return HTTP 503 with `Retry-After`.
4. Keep Postgres stopped until startup completes. After the gateway takes
   over, `/health` must remain HTTP 200 with `status: degraded` and
   `reason: postgres unavailable`; the core Postgres readiness endpoint
   must return HTTP 503 `NOT_SERVING`. Capture both responses at this point,
   not only during the early startup phase.
5. Read network policies using the normal authenticated operator client.
   Then attempt to create the synthetic policy. Expect `UNAVAILABLE`
   (HTTP 503) with `network-policy store is degraded` and
   `nothing was changed`. List policies again and confirm the synthetic
   policy was not added. Existing persisted policies may not be loaded
   while the fallback is active; a successful read does not prove durable
   policies are present.
6. Inspect the tunnel log during startup and after handover: once the
   early listener is serving, there must be no continuing HTTP
   `connection refused` loop. Capture the control-plane backend status and
   its advisory `containarium.core_postgres` readiness check: the daemon is
   connected but its database-backed stores are not ready. Control-plane
   status is not asserted by the local HTTP tests.
7. Start Postgres with `incus start <core-postgres-container>`, wait until
   the database is reachable, then restart the daemon. Expect `/health`
   HTTP 200 `status: healthy` and core readiness HTTP 200 `SERVING`. Confirm
   the previously persisted policy returns and the synthetic policy write
   succeeds. Remove the synthetic policy after recording the result.
8. If validating `CONTAINARIUM_RESTART_ON_POSTGRES_RECOVERY=1`, repeat the
   outage with that setting and a supervisor that restarts nonzero exits.
   When Postgres returns, expect the daemon to exit 75 after three
   consecutive successful pings and the minimum uptime (default two
   minutes), then start with its normal stores. This is a supervised
   restart; general recovery without restarting is #2855.

Restore Postgres and the daemon even if a step fails. Post the results on
#3044, #3130 and the #3132 verification queue, naming the deployed commit
and linking evidence that outlives the host. Leave any unexecuted step
explicitly unverified; a merged PR or a local test run is not deployed
verification.
