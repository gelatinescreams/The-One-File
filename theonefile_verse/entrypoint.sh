#!/bin/sh
set -e
chown -R appuser:appgroup /app/data
if ! su-exec appuser test -w /app/data; then
  echo "FATAL: /app/data is not writable by appuser" >&2
  exit 1
fi
exec su-exec appuser bun run src/index.ts
