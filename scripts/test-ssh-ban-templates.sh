#!/usr/bin/env bash
# Exercise the real policy locals/variables/templates without cloud providers.
set -euo pipefail
repo_root="$(cd "$(dirname "$0")/.." && pwd)"
terraform_bin="${TERRAFORM:-terraform}"
test_dir="$(mktemp -d)"
trap 'rm -rf "$test_dir"' EXIT
module="$repo_root/terraform/modules/containarium"
cp "$module/variables.tf" "$module/ssh-ban-policy.tf" "$test_dir/"
cp -R "$module/scripts" "$test_dir/scripts"
cp "$module/tests/ssh-ban.tftest.hcl" "$test_dir/"
"$terraform_bin" -chdir="$test_dir" init -backend=false -input=false >/dev/null
"$terraform_bin" -chdir="$test_dir" validate
"$terraform_bin" -chdir="$test_dir" test -no-color
