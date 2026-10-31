# Sentinel backend SSH host-key pins

Sentinel verifies two identities separately: the offered user key/certificate
controls who may log in, and the backend host key identifies the selected SSH
server. User authorization does not establish the backend's identity.

Keysync-generated routes reference `/etc/sshpiper/known_hosts`. Install this
file through a trusted operator/configuration-management channel. Keysync does
not learn host keys from `/authorized-keys` or from an SSH network scan.
The enforce-mode router requires a nonempty `known_hosts` file and carries its
bytes in the upstream response. The YAML routing plugin reads the same file.
The existing upstream verifier rejects malformed data, an unknown endpoint,
a mismatched host key and revoked keys.

## Provisioning and upgrade

1. Identify the **actual SSH ingress** selected for each backend. Read the host
   public key of that listener through a trusted administrative channel and
   verify its fingerprint. It may use a dedicated sshd configuration. Do not
   substitute a user public key, a user CA key or Sentinel's frontend host key.
2. Create OpenSSH known-hosts entries for the exact target names/addresses and
   ports in the generated routes. For example (replace the key placeholders):

   ```text
   backend.example ssh-ed25519 <trusted-base64-public-key>
   [backend.example]:2222 ssh-ed25519 <trusted-base64-public-key>
   [127.0.0.1]:20022 ssh-ed25519 <trusted-tunnel-backend-public-key>
   ```

   The loopback example pins the backend reached through that tunnel port,
   not the loopback machine's own SSH server. Use distinct endpoint entries;
   avoid broad wildcard trust. Reassigning a tunnel port to a different
   backend requires an authorized pin update.
3. Install the file as root-owned and not writable by other users; public keys
   may be mode `0644` so a non-root routing plugin can read them. The parent
   directory must also be operator-controlled. For example, after preparing
   and verifying `backend_known_hosts` locally:

   ```bash
   sudo install -o root -g root -m 0644 backend_known_hosts /etc/sshpiper/known_hosts.new
   sudo mv /etc/sshpiper/known_hosts.new /etc/sshpiper/known_hosts
   ```

4. Upgrade Sentinel and regenerate its keysync config through the normal
   manager sync. Verify each managed `to:` block has
   `known_hosts: /etc/sshpiper/known_hosts` before considering the migration
   complete. Existing on-disk YAML routes are not rewritten by the plugin
   alone. Coordinate a maintenance window if necessary: stop SSH ingress,
   install pins, upgrade/regenerate configuration, then resume ingress.
5. Verify a normal login and a deliberately incorrect pin on an isolated test
   backend. A wrong/missing pin must refuse a new connection, even if the
   offered user key is authorized. Maintain an independent administrative
   access path while testing changes.

An old enforce-router config with no `known_hosts` now refuses connections.
A missing or empty trust file also refuses connections; there is no automatic
fallback to ignoring host keys. Legacy `ignore_hostkey` is accepted by the
router parser but cannot bypass required pins. Keysync no longer emits it.
Manually maintained, unpinned YAML routes outside keysync remain an operator
migration responsibility.

## Rotation and failure behavior

Publish old and new verified host keys together for the endpoint, rotate the
backend listener, then remove the old key. Replace the trust file atomically;
do not truncate and rewrite it in place. New routing attempts read the current
file. Existing established SSH sessions are not re-authenticated or revoked
by a pin change. For an emergency revocation, also terminate affected sessions
through the existing session-control mechanism.

Keep trusted pins during a keysync HTTP outage. Do not automatically replace
pins when a connection fails or an unknown key appears. Request signing on the
HTTP sync path does not by itself authenticate a response; distributing host
keys through that response would require its own authenticated trust design.

## Tests

Router unit tests reject absent, missing, empty and unreadable trust files.
The renderer/router contract test checks generated pins for advertised and
legacy tunnel ports. `TestAuthzRouterAdapterVerifiesBackendHandshake` connects
the actual router and adapter to an in-process SSH server. Its companion
`TestYAMLRouterAdapterVerifiesBackendHandshake` uses a real YAML plugin supplied
by `SSH_AUTHZ_YAML`. Both cover correct/wrong keys, wrong ports, malformed and
missing pins, and a dual-key rotation window. They exercise real SSH handshakes
without requiring an external sshd or model service.

The full sshpiperd authz/session-chain tests remain available under the
`integration` build tag with the existing `SSH_AUTHZ_*` binary prerequisites.
