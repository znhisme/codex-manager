#!/usr/bin/env sh
set -eu

DEFAULT_APP_DIR="/app"
WORK_ROOT="${SELF_UPDATE_WORK_DIR:-/app/data/self_update}"
CURRENT_DIR="$WORK_ROOT/current"
EXECUTABLE_NAME="${SELF_UPDATE_EXECUTABLE_NAME:-codex-register}"

mkdir -p /app/data /app/logs "$WORK_ROOT"
export APP_DATA_DIR="${APP_DATA_DIR:-/app/data}"
export APP_LOGS_DIR="${APP_LOGS_DIR:-/app/logs}"

if [ "$#" -gt 0 ]; then
  exec "$@"
fi

if [ -x "$CURRENT_DIR/$EXECUTABLE_NAME" ]; then
  cd "$CURRENT_DIR"
  set -- "./$EXECUTABLE_NAME"
else
  cd "$DEFAULT_APP_DIR"
  set -- python /app/webui.py
fi

if command -v xvfb-run >/dev/null 2>&1; then
  if [ -z "${DISPLAY:-}" ] && [ "${ENABLE_XVFB:-1}" = "1" ]; then
    exec xvfb-run -a -s "-screen 0 1280x720x24" "$@"
  fi
fi

exec "$@"
