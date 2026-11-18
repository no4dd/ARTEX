#!/bin/sh
set -eu
python3 /app/scripts/plan_target_forward.py &
exec /app/start.sh "$@"
