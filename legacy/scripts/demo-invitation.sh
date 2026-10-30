#!/bin/sh
set -eu
task_repo="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$task_repo"
printf '%s\n' 'RunLater local-only invitation demo: ephemeral identities, disposable SQLite, intercepted receivers; no live service or provider changes.'
exec ./scripts/test-invitation-delivery.sh
