#!/bin/sh
#
# The box's forced-command session (#1190).
#
# dropbear runs this instead of agent-box directly, so that the tenant's
# secrets are in the environment before the MCP server starts. Doing it here
# rather than in the entrypoint is the point: the entrypoint runs once at pod
# start, while this runs per session, so a refreshed Secret reaches the next
# session without the box restarting.
set -eu

. /usr/local/lib/containarium/secrets-env.sh

exec /usr/local/bin/agent-box "$@"
