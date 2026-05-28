#!/usr/bin/env bash
# Runs inside the container as the post-receive deploy hook (configured
# via mcp__push --deploy_cmd "bash deploy.sh"). Four jobs:
#   1. Build the Go binary in-place (assumes the container image has
#      a Go toolchain — typical for an LXC bootstrapped with golang).
#   2. Snapshot the current commit SHA for visibility.
#   3. Install the systemd unit if it isn't installed yet.
#   4. Restart the service so the new code takes effect.
set -euo pipefail

cd "$HOME/work"

go build -trimpath -o helloworld-go .

git --git-dir="$HOME/work.git" rev-parse HEAD > commit.txt

sudo cp helloworld.service /etc/systemd/system/helloworld.service
sudo systemctl daemon-reload
sudo systemctl enable --now helloworld.service
sudo systemctl restart helloworld.service
