#!/bin/sh
set -eu
profile_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec "$profile_dir/../.venv/bin/python" "$profile_dir/../runtime/candidate/pg_i7.py" --profile public "$@"
