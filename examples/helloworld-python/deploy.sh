#!/usr/bin/env bash
# Runs inside the container as the post-receive deploy hook (configured
# via mcp__push --deploy_cmd "bash deploy.sh"). Four jobs:
#   1. Install Python deps (containarium-telemetry for OTel wiring).
#   2. Snapshot the current commit SHA so app.py can read it at request time.
#   3. Install the systemd unit if it isn't installed yet.
#   4. Restart the service so the new code takes effect.
set -euo pipefail

cd "$HOME/work"

# --user installs into ~/.local; the systemd unit runs as the same user,
# so user-site packages are on its sys.path. --break-system-packages is
# the PEP 668 escape hatch for Ubuntu 24.04+ — required because we're
# not using a venv for this demo.
pip install --user --break-system-packages -r requirements.txt

git --git-dir="$HOME/work.git" rev-parse HEAD > commit.txt

sudo cp helloworld.service /etc/systemd/system/helloworld.service
sudo systemctl daemon-reload
sudo systemctl enable --now helloworld.service
sudo systemctl restart helloworld.service
