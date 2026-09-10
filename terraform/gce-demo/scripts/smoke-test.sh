#!/usr/bin/env bash
# Smoke-test a freshly-applied terraform/gce-demo cluster.
#
# Run AFTER `terraform apply`. Verifies four things in order:
#
#   1. The containarium daemon is running on the backend at the
#      expected version.
#   2. The public HTTPS endpoint serves a valid cert and the API
#      responds (401 without a token) — i.e. DNS-less reachability of
#      sentinel :443 -> Caddy -> backend daemon, with a real cert.
#   3. A freshly-issued JWT is minted on the backend.
#   4. That JWT authenticates against /v1/containers over HTTPS and the
#      API returns a sensible list.
#
# Architecture notes (why this script does NOT just `ssh` the sentinel):
#   - The sentinel's port 22 is sshpiper (the tenant SSH proxy), not a
#     host shell; its management sshd is on :2222 and firewalled to the
#     VPC. So the daemon binary + jwt.secret are operated on the BACKEND
#     over IAP, not on the sentinel.
#   - The daemon API (:8080) is NOT exposed publicly. It's reached
#     through the sentinel's Caddy over HTTPS at the base domain.
#
# Connections to the public endpoint use `curl --resolve` so the check
# works the moment `terraform apply` finishes — before DNS propagates —
# while still validating the real Let's Encrypt cert (SNI = base domain).
#
# Exit 0 if every check passes; 1 on the first failure (the rest are
# typically already broken once an early check fails). Run from
# terraform/gce-demo/ or pass --tf-dir=<path>.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TF_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
EXPECTED_VERSION="${EXPECTED_VERSION:-}"  # leave empty to skip version assertion

# ---- argument parsing -----------------------------------------------

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tf-dir=*)
      TF_DIR="${1#--tf-dir=}"
      shift
      ;;
    --expected-version=*)
      EXPECTED_VERSION="${1#--expected-version=}"
      shift
      ;;
    -h|--help)
      cat <<EOF
Usage: smoke-test.sh [--tf-dir=PATH] [--expected-version=X.Y.Z]

  --tf-dir=PATH         Terraform working directory (default: parent of this script).
  --expected-version    If set, fail when 'containarium version' on the backend
                        doesn't match. Useful in CI; skip locally.

Run AFTER 'terraform apply' has produced state in --tf-dir.
EOF
      exit 0
      ;;
    *)
      echo "unknown arg: $1" >&2
      exit 64
      ;;
  esac
done

# ---- helpers ---------------------------------------------------------

CHECK_NUM=0
fail() {
  echo "  ✗ FAIL: $*" >&2
  exit 1
}

check() {
  CHECK_NUM=$((CHECK_NUM + 1))
  echo
  echo "──[$CHECK_NUM] $*"
}

ok() {
  echo "  ✓ ok"
}

tf_out() {
  terraform -chdir="$TF_DIR" output -raw "$1" 2>/dev/null \
    || fail "terraform output '$1' missing — did you run 'terraform apply' first?"
}

# curl the public API endpoint by pinning the base domain to the
# sentinel IP (DNS-independent), while still verifying the real cert.
api_curl() {
  # usage: api_curl <path> [extra curl args...]
  local path="$1"; shift
  curl -sS --max-time 20 --resolve "${BASE_DOMAIN}:443:${SENTINEL_IP}" "$@" \
    "https://${BASE_DOMAIN}${path}"
}

# ---- preflight -------------------------------------------------------

if [[ ! -f "$TF_DIR/terraform.tfstate" ]] && [[ ! -d "$TF_DIR/.terraform" ]]; then
  fail "no Terraform state in $TF_DIR — run 'terraform apply' first"
fi
command -v gcloud >/dev/null || fail "gcloud not on PATH"
command -v curl >/dev/null   || fail "curl not on PATH"

PROJECT_ID="$(tf_out project_id)"
ZONE="$(tf_out zone)"
SENTINEL_IP="$(tf_out sentinel_ip)"
SPOT_VM="$(tf_out spot_vm_name)"
BASE_DOMAIN="$(tf_out demo_base_domain)"

echo "Targeting:"
echo "  project:     $PROJECT_ID"
echo "  zone:        $ZONE"
echo "  backend:     $SPOT_VM (via IAP)"
echo "  sentinel IP: $SENTINEL_IP"
echo "  base domain: $BASE_DOMAIN"

if [[ "$BASE_DOMAIN" == \(* ]]; then
  fail "app-hosting/base_domain not configured ($BASE_DOMAIN) — set base_domain in tfvars"
fi

# ---- 1. Daemon running on backend -----------------------------------

check "Daemon is running on backend at expected version"
ACTUAL_VERSION="$(gcloud compute ssh "$SPOT_VM" \
  --project="$PROJECT_ID" --zone="$ZONE" --tunnel-through-iap \
  --command='sudo /usr/local/bin/containariumd version' --quiet 2>/dev/null \
  | head -1 | tr -d '[:space:]')" || fail "couldn't reach the daemon binary over IAP"
echo "  daemon reports: $ACTUAL_VERSION"
if [[ -n "$EXPECTED_VERSION" ]] && [[ "$ACTUAL_VERSION" != *"$EXPECTED_VERSION"* ]]; then
  fail "expected version to contain '$EXPECTED_VERSION', got '$ACTUAL_VERSION'"
fi
ok

# ---- 2. Public endpoint: valid cert + API responding ----------------

check "Public HTTPS endpoint has a valid cert and the API is up"
PROBE="$(api_curl /v1/containers -o /dev/null -w '%{http_code}:%{ssl_verify_result}' \
  || fail "couldn't reach https://${BASE_DOMAIN} via sentinel ${SENTINEL_IP}:443 — sentinel/Caddy may still be initializing, or the cert isn't issued yet (TLS error)")"
HTTP_CODE="${PROBE%%:*}"
TLS_VERIFY="${PROBE##*:}"
echo "  https://${BASE_DOMAIN}/v1/containers -> HTTP $HTTP_CODE (cert verify=$TLS_VERIFY)"
[[ "$TLS_VERIFY" == "0" ]] || fail "TLS cert did not verify (verify=$TLS_VERIFY) — ACME may not have completed; check DNS for ${BASE_DOMAIN}"
[[ "$HTTP_CODE" == "401" || "$HTTP_CODE" == "200" ]] \
  || fail "API answered with unexpected status $HTTP_CODE (expected 401 unauth or 200)"
ok

# ---- 3. JWT issuance on the backend ---------------------------------

check "JWT issuance on the backend"
TOKEN_FILE="$(mktemp)"
trap 'rm -f "$TOKEN_FILE"' EXIT

gcloud compute ssh "$SPOT_VM" \
  --project="$PROJECT_ID" --zone="$ZONE" --tunnel-through-iap \
  --command='sudo /usr/local/bin/containariumd token generate \
              --username smoke --roles admin --expiry 1h \
              --secret-file /etc/containarium/jwt.secret 2>/dev/null \
              | grep -E "^eyJ"' --quiet 2>/dev/null \
  > "$TOKEN_FILE" || true
[[ -s "$TOKEN_FILE" ]] || fail "JWT issuance produced empty output (jwt.secret missing on backend?)"
echo "  JWT issued ($(wc -c < "$TOKEN_FILE" | tr -d ' ') bytes)"
ok

# ---- 4. Authenticated API call --------------------------------------

check "Authenticated API call returns JSON"
RESPONSE="$(api_curl /v1/containers -H "Authorization: Bearer $(cat "$TOKEN_FILE")" \
  || fail "authenticated curl to https://${BASE_DOMAIN} failed")"
echo "$RESPONSE" | grep -q '"containers"' \
  || fail "API responded but didn't contain a containers field; got: $RESPONSE"
COUNT="$(echo "$RESPONSE" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("totalCount",0))' 2>/dev/null || echo "?")"
echo "  API returned $COUNT container(s) — fresh cluster expected to be 0"
ok

# ---- summary ---------------------------------------------------------

echo
echo "All $CHECK_NUM checks passed. Cluster is ready for the demo flow."
echo
echo "Next: issue a 24h JWT (see 'terraform output next_steps'), wire"
echo "Claude Code's MCP server at https://${BASE_DOMAIN}, and drive the"
echo "demo prompt."
