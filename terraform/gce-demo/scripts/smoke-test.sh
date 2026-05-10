#!/usr/bin/env bash
# Smoke-test a freshly-applied terraform/gce-demo cluster.
#
# Run AFTER `terraform apply`. Verifies four things in order:
#
#   1. gcloud SSH to the sentinel works.
#   2. The containarium daemon is running on the backend at the
#      expected version.
#   3. A freshly-issued JWT actually authenticates against
#      /v1/containers.
#   4. The platform MCP HTTP API returns a sensible empty list.
#
# Doesn't touch DNS — that's manual on non-Cloud-DNS providers and
# the script wants to work for everyone. Doesn't tear down — leave
# that to the operator.
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

# ---- preflight -------------------------------------------------------

if [[ ! -f "$TF_DIR/terraform.tfstate" ]] && [[ ! -d "$TF_DIR/.terraform" ]]; then
  fail "no Terraform state in $TF_DIR — run 'terraform apply' first"
fi
command -v gcloud >/dev/null || fail "gcloud not on PATH"
command -v curl >/dev/null   || fail "curl not on PATH"

PROJECT_ID="$(tf_out project_id)"
ZONE="$(tf_out zone)"
SENTINEL_IP="$(tf_out sentinel_ip)"
SENTINEL_VM="$(tf_out sentinel_vm_name)"
SPOT_VM="$(tf_out spot_vm_name)"

echo "Targeting:"
echo "  project: $PROJECT_ID"
echo "  zone:    $ZONE"
echo "  sentinel: $SENTINEL_VM ($SENTINEL_IP)"
echo "  backend:  $SPOT_VM"

# ---- 1. SSH to sentinel ---------------------------------------------

check "SSH to the sentinel"
gcloud compute ssh "$SENTINEL_VM" \
  --project="$PROJECT_ID" --zone="$ZONE" \
  --command='echo ok' --quiet 2>/dev/null \
  | grep -q "^ok$" || fail "couldn't SSH to sentinel — check IAM and allowed_ssh_sources"
ok

# ---- 2. Daemon running on backend -----------------------------------

check "Daemon is running on backend at expected version"
ACTUAL_VERSION="$(gcloud compute ssh "$SPOT_VM" \
  --project="$PROJECT_ID" --zone="$ZONE" --tunnel-through-iap \
  --command='sudo /usr/local/bin/containarium version' --quiet 2>/dev/null \
  | head -1 | tr -d '[:space:]')" || fail "couldn't reach the daemon binary"
echo "  daemon reports: $ACTUAL_VERSION"
if [[ -n "$EXPECTED_VERSION" ]] && [[ "$ACTUAL_VERSION" != *"$EXPECTED_VERSION"* ]]; then
  fail "expected version to contain '$EXPECTED_VERSION', got '$ACTUAL_VERSION'"
fi
ok

# ---- 3. JWT issuance + API auth -------------------------------------

check "JWT issuance + authenticated API call"
TOKEN_FILE="$(mktemp)"
trap 'rm -f "$TOKEN_FILE"' EXIT

gcloud compute ssh "$SENTINEL_VM" \
  --project="$PROJECT_ID" --zone="$ZONE" \
  --command='sudo /usr/local/bin/containarium token generate \
              --username smoke --roles admin --expiry 1h \
              --secret-file /etc/containarium/jwt.secret 2>/dev/null \
              | grep -E "^eyJ"' --quiet 2>/dev/null \
  > "$TOKEN_FILE"
[[ -s "$TOKEN_FILE" ]] || fail "JWT issuance produced empty output"
echo "  JWT issued ($(wc -c < "$TOKEN_FILE" | tr -d ' ') bytes)"

# ---- 4. API answers --------------------------------------------------

check "Authenticated API call returns JSON"
RESPONSE="$(curl -sS --max-time 15 \
  -H "Authorization: Bearer $(cat "$TOKEN_FILE")" \
  "http://$SENTINEL_IP:8080/v1/containers" \
  || fail "curl to http://$SENTINEL_IP:8080 failed — sentinel may still be initializing")"
echo "$RESPONSE" | grep -q '"containers"' \
  || fail "API responded but didn't contain a containers field; got: $RESPONSE"
COUNT="$(echo "$RESPONSE" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("totalCount",0))' 2>/dev/null || echo "?")"
echo "  API returned $COUNT container(s) — fresh cluster expected to be 0"
ok

# ---- summary ---------------------------------------------------------

echo
echo "All $CHECK_NUM checks passed. Cluster is ready for the demo flow."
echo
echo "Next: configure DNS (per README §'Without Cloud DNS' on GoDaddy /"
echo "Cloudflare / Route 53), wire Claude Code with the JWT, and drive"
echo "the demo prompt."
