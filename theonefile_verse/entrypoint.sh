#!/bin/sh
chown -R appuser:appgroup /app/data
exec su-exec appuser bun run src/index.ts
