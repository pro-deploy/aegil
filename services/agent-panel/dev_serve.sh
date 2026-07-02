#!/usr/bin/env bash
# Dev-запуск панели для локального preview (НЕ для прода). Токен демонстрационный.
cd "$(dirname "$0")"
export ADMINCHAT_TOKEN="${ADMINCHAT_TOKEN:-dev-token}"
export ADMINCHAT_OPERATOR="${ADMINCHAT_OPERATOR:-max}"
export RCA_URL="${RCA_URL:-http://127.0.0.1:9107}"
export ADMINCHAT_POLL_SECONDS="${ADMINCHAT_POLL_SECONDS:-8}"
exec python3 -m uvicorn app:app --host 127.0.0.1 --port 9109 --log-level warning
