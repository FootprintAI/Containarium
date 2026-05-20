#!/usr/bin/env bash
# Runs inside the container as the post-receive deploy hook (configured
# via mcp__push --deploy_cmd "bash deploy.sh"). Three jobs:
#   1. Snapshot the current commit SHA so app.py can read it at request time.
#   2. Install the systemd unit if it isn't installed yet.
#   3. Restart the service so the new code takes effect.
set -euo pipefail

cd "$HOME/work"

git --git-dir="$HOME/work.git" rev-parse HEAD > commit.txt

sudo cp helloworld.service /etc/systemd/system/helloworld.service
sudo systemctl daemon-reload
sudo systemctl enable --now helloworld.service
sudo systemctl restart helloworld.service
