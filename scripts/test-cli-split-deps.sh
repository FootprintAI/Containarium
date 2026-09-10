#!/usr/bin/env bash
# Dependency-graph gate for the CLI client/server split (#1778).
#
# Proves the CODE is out of the containarium client's link, not just its
# cobra registration — a forgotten !containarium_client tag on a new
# server-side file that imports one of these packages fails here, at PR
# time, instead of only showing up as a bigger binary or a linked-in
# Postgres driver nobody meant to ship to laptops.
#
# pkg/core/incus is deliberately NOT on this list: incus.ContainerInfo /
# incus.ServerInfo are the return types of every internal/client call, so
# the package stays linked until the types-only-package follow-up (design
# doc, Open decision 3) moves those two structs out of it.
set -uo pipefail
cd "$(dirname "$0")/.."

FORBIDDEN=(
  "github.com/footprintai/containarium/pkg/core/container"
  "github.com/footprintai/containarium/internal/server"
  "github.com/footprintai/containarium/internal/sentinel"
  "github.com/footprintai/containarium/internal/hosting"
  "github.com/footprintai/containarium/internal/hypervisor"
  "github.com/jackc/pgx"
)

deps="$(go list -deps -tags containarium_client ./cmd/containarium)"
if [ -z "$deps" ]; then
  echo "FAIL  'go list -deps -tags containarium_client ./cmd/containarium' produced no output — the command itself is broken, not passing"
  exit 1
fi

fail=0
for pkg in "${FORBIDDEN[@]}"; do
  hits="$(echo "$deps" | grep -F "$pkg" || true)"
  if [ -n "$hits" ]; then
    echo "FAIL  $pkg is linked into the containarium client:"
    echo "$hits" | sed 's/^/        /'
    fail=1
  else
    echo "PASS  $pkg absent"
  fi
done

exit $fail
