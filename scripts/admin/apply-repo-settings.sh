#!/usr/bin/env bash
# Apply the supply-chain repository settings decided on #2649 (story 2, #2792).
#
# This needs REPOSITORY ADMIN. It is run by a human admin, not by CI and not by
# an agent. The default is a DRY RUN: it reads the live settings, prints the
# change it would make for each setting, and writes nothing. Pass --apply to
# write. See docs/security/REPO-SETTINGS-RUNBOOK.md.
#
# Usage:
#   scripts/admin/apply-repo-settings.sh                # dry run, read-only
#   scripts/admin/apply-repo-settings.sh --apply        # write, then read back
#   scripts/admin/apply-repo-settings.sh --check-allow-list
#       # offline: every third-party `uses:` under .github/ is covered by the
#       # allow-list below (CI runs this so the list cannot lock CI out)
#
# Environment: REPO (default FootprintAI/Containarium), BRANCH (default main),
# GH (the gh binary; tests substitute a fake).
#
# Branch protection is read-modify-write: the live protection is read, only the
# review/conversation fields are changed, and everything else is sent back
# unchanged, so the required status-check contexts (with their app ids),
# `strict`, enforce_admins, linear history, force-push and deletion flags
# survive. The script aborts rather than guess if the live protection has
# push restrictions or review dismissal/bypass lists it does not model.
set -euo pipefail

REPO=${REPO:-FootprintAI/Containarium}
BRANCH=${BRANCH:-main}
GH=${GH:-gh}

# Allow-list per docs/security/ACTION-ALLOW-LIST.md, plus the
# dependency-review action that #2794 adds. GitHub-owned actions (actions/*,
# github/*) are allowed by github_owned_allowed, not by pattern.
ALLOWED_PATTERNS=(
  'docker/setup-buildx-action@*'
  'docker/setup-qemu-action@*'
  'docker/login-action@*'
  'docker/build-push-action@*'
  'aquasecurity/trivy-action@*'
  'securego/gosec@*'
  'ossf/scorecard-action@*'
  'sigstore/cosign-installer@*'
  'anchore/sbom-action/download-syft@*'
  'azure/setup-helm@*'
  'hashicorp/setup-terraform@*'
  'softprops/action-gh-release@*'
  'pypa/gh-action-pypi-publish@*'
)
GITHUB_OWNED_OWNERS_RE='^(actions|github)/'

die() { echo "error: $*" >&2; exit 1; }

# Offline: is every third-party `uses:` in .github covered?
check_allow_list() {
  local root=${1:-.github} bad=0 ref pat ok
  while IFS= read -r ref; do
    [[ "$ref" == ./* || "$ref" == docker://* ]] && continue
    [[ "$ref" =~ $GITHUB_OWNED_OWNERS_RE ]] && continue
    ok=0
    for pat in "${ALLOWED_PATTERNS[@]}"; do
      # shellcheck disable=SC2053
      if [[ "$ref" == $pat ]]; then ok=1; break; fi
    done
    if [[ $ok -eq 0 ]]; then echo "NOT ALLOW-LISTED: $ref"; bad=1; fi
  done < <(grep -rhoE '^[[:space:]]*(-[[:space:]]+)?uses:[[:space:]]*[^[:space:]#]+' "$root" \
             --include='*.yml' --include='*.yaml' \
           | sed -E 's/^[[:space:]]*(-[[:space:]]+)?uses:[[:space:]]*//; s/^["'"'"']//; s/["'"'"']$//' | sort -u)
  return "$bad"
}

if [[ "${1:-}" == "--check-allow-list" ]]; then
  check_allow_list "${2:-.github}"
  exit $?
fi

APPLY=0
case "${1:-}" in
  '') ;;
  --apply) APPLY=1 ;;
  *) die "unknown argument: $1 (use --apply or --check-allow-list)" ;;
esac

command -v jq >/dev/null || die "jq is required"

api_get() { "$GH" api "$1"; }
# api_send METHOD PATH [JSON-body]; writes only reach here under --apply.
api_send() {
  local method=$1 path=$2 body=${3:-}
  if [[ -n "$body" ]]; then
    printf '%s' "$body" | "$GH" api -X "$method" "$path" --input - >/dev/null
  else
    "$GH" api -X "$method" "$path" >/dev/null
  fi
}

# Probe endpoints that answer 204 (enabled) or 404 (disabled).
probe_enabled() { if "$GH" api "$1" >/dev/null 2>&1; then echo true; else echo false; fi; }

# read_state: one JSON document with every setting this script manages.
read_state() {
  local prot perms wf sel repo auto alerts
  prot=$(api_get "repos/$REPO/branches/$BRANCH/protection")
  perms=$(api_get "repos/$REPO/actions/permissions")
  wf=$(api_get "repos/$REPO/actions/permissions/workflow")
  if [[ $(jq -r .allowed_actions <<<"$perms") == selected ]]; then
    sel=$(api_get "repos/$REPO/actions/permissions/selected-actions")
  else
    sel='null'
  fi
  repo=$(api_get "repos/$REPO")
  # automated-security-fixes answers 200 with {"enabled": bool} either way.
  auto=$(api_get "repos/$REPO/automated-security-fixes" | jq '.enabled == true')
  alerts=$(probe_enabled "repos/$REPO/vulnerability-alerts")
  jq -n --argjson prot "$prot" --argjson perms "$perms" --argjson wf "$wf" \
        --argjson sel "$sel" --argjson repo "$repo" \
        --argjson auto "$auto" --argjson alerts "$alerts" '
    {
      branch_protection: {
        contexts: ([$prot.required_status_checks.checks[]? | .context] | sort),
        strict: ($prot.required_status_checks.strict // false),
        enforce_admins: ($prot.enforce_admins.enabled // false),
        require_code_owner_reviews: ($prot.required_pull_request_reviews.require_code_owner_reviews // false),
        required_approving_review_count: ($prot.required_pull_request_reviews.required_approving_review_count // 0),
        dismiss_stale_reviews: ($prot.required_pull_request_reviews.dismiss_stale_reviews // false),
        required_conversation_resolution: ($prot.required_conversation_resolution.enabled // false)
      },
      actions: {
        allowed_actions: $perms.allowed_actions,
        sha_pinning_required: ($perms.sha_pinning_required // false),
        github_owned_allowed: (if $sel == null then null else $sel.github_owned_allowed end),
        verified_allowed: (if $sel == null then null else $sel.verified_allowed end),
        patterns_allowed: (if $sel == null then null else ($sel.patterns_allowed | sort) end),
        default_workflow_permissions: $wf.default_workflow_permissions,
        can_approve_pull_request_reviews: $wf.can_approve_pull_request_reviews
      },
      security: {
        secret_scanning: ($repo.security_and_analysis.secret_scanning.status // "unknown"),
        secret_scanning_push_protection: ($repo.security_and_analysis.secret_scanning_push_protection.status // "unknown"),
        dependabot_alerts: $alerts,
        dependabot_security_updates: $auto
      }
    }'
}

# desired_state: the target for the settings this script owns; every other
# field is taken from the live state so the diff shows only intended changes.
desired_state() {
  local live=$1 patterns
  patterns=$(printf '%s\n' "${ALLOWED_PATTERNS[@]}" | jq -R . | jq -s 'sort')
  jq --argjson patterns "$patterns" '
    .branch_protection.require_code_owner_reviews = true
    | .branch_protection.required_approving_review_count = ([.branch_protection.required_approving_review_count, 1] | max)
    | .branch_protection.dismiss_stale_reviews = true
    | .branch_protection.required_conversation_resolution = true
    | .actions.allowed_actions = "selected"
    | .actions.sha_pinning_required = true
    | .actions.github_owned_allowed = true
    | .actions.verified_allowed = false
    | .actions.patterns_allowed = $patterns
    | .actions.default_workflow_permissions = "read"
    | .actions.can_approve_pull_request_reviews = false
    | .security.secret_scanning = "enabled"
    | .security.secret_scanning_push_protection = "enabled"
    | .security.dependabot_alerts = true
    | .security.dependabot_security_updates = true' <<<"$live"
}

# protection_body: the PUT body, rebuilt from the live protection (not from the
# summary above) so nothing the script does not own is dropped.
protection_body() {
  local prot=$1
  jq '
    if (.restrictions != null) then error("live protection has push restrictions; set them by hand") else . end
    | if (.required_pull_request_reviews.dismissal_restrictions != null
          or .required_pull_request_reviews.bypass_pull_request_allowances != null)
      then error("live protection has dismissal/bypass lists; set the review rule by hand") else . end
    | {
        required_status_checks: (if .required_status_checks == null then null else {
            strict: .required_status_checks.strict,
            checks: [.required_status_checks.checks[] | {context, app_id}]
          } end),
        enforce_admins: .enforce_admins.enabled,
        required_pull_request_reviews: {
          dismiss_stale_reviews: true,
          require_code_owner_reviews: true,
          required_approving_review_count: ([.required_pull_request_reviews.required_approving_review_count // 0, 1] | max),
          require_last_push_approval: (.required_pull_request_reviews.require_last_push_approval // false)
        },
        restrictions: null,
        required_linear_history: (.required_linear_history.enabled // false),
        allow_force_pushes: (.allow_force_pushes.enabled // false),
        allow_deletions: (.allow_deletions.enabled // false),
        block_creations: (.block_creations.enabled // false),
        required_conversation_resolution: true,
        lock_branch: (.lock_branch.enabled // false),
        allow_fork_syncing: (.allow_fork_syncing.enabled // false)
      }' <<<"$prot"
}

show_diff() {
  local before=$1 after=$2
  diff -u <(jq -S . <<<"$before") <(jq -S . <<<"$after") \
    --label "$3" --label "$4" || true
}

before=$(read_state)
desired=$(desired_state "$before")

echo "== Before (live read-back, $REPO, branch $BRANCH) =="
jq -S . <<<"$before"
echo
echo "== Planned change (live -> desired) =="
if [[ "$before" == "$desired" ]]; then echo "(none: already compliant)"; else show_diff "$before" "$desired" live desired; fi
echo

if [[ $APPLY -eq 0 ]]; then
  echo "DRY RUN: nothing was written. Re-run with --apply (repository admin) to apply."
  exit 0
fi

echo "== Applying =="
prot=$(api_get "repos/$REPO/branches/$BRANCH/protection")
body=$(protection_body "$prot")
api_send PUT "repos/$REPO/branches/$BRANCH/protection" "$body"
echo "branch protection: written"

api_send PUT "repos/$REPO/actions/permissions" \
  '{"enabled":true,"allowed_actions":"selected","sha_pinning_required":true}'
patterns=$(printf '%s\n' "${ALLOWED_PATTERNS[@]}" | jq -R . | jq -s .)
api_send PUT "repos/$REPO/actions/permissions/selected-actions" \
  "$(jq -n --argjson p "$patterns" '{github_owned_allowed:true, verified_allowed:false, patterns_allowed:$p}')"
api_send PUT "repos/$REPO/actions/permissions/workflow" \
  '{"default_workflow_permissions":"read","can_approve_pull_request_reviews":false}'
echo "actions permissions: written"

api_send PATCH "repos/$REPO" \
  '{"security_and_analysis":{"secret_scanning":{"status":"enabled"},"secret_scanning_push_protection":{"status":"enabled"}}}'
api_send PUT "repos/$REPO/vulnerability-alerts"
api_send PUT "repos/$REPO/automated-security-fixes"
echo "security settings: written"
echo

after=$(read_state)
echo "== After (live read-back) =="
jq -S . <<<"$after"
echo

rc=0
if [[ "$after" != "$desired" ]]; then
  echo "MISMATCH: read-back differs from desired (--- desired, +++ read-back):"; show_diff "$desired" "$after" desired read-back; rc=1
fi
# Required checks and enforce_admins must be exactly what they were.
for k in contexts strict enforce_admins; do
  if [[ "$(jq -c ".branch_protection.$k" <<<"$before")" != "$(jq -c ".branch_protection.$k" <<<"$after")" ]]; then
    echo "REGRESSION: branch_protection.$k changed"; rc=1
  fi
done
[[ $rc -eq 0 ]] && echo "OK: every setting reads back as desired; contexts, strict and enforce_admins unchanged."
exit "$rc"
