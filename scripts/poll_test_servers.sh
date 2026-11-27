#!/usr/bin/env bash

TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-10}"

poll_server() {
  local name="$1"
  local port="$2"
  local url="http://localhost:${port}/health"
  local deadline=$((SECONDS + TIMEOUT_SECONDS))

  echo "Polling ${name} (${url})..."
  until [[ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "$url")" == "200" ]]; do
    if ((SECONDS >= deadline)); then
      echo "Timed out waiting for ${name} (${url})" >&2
      exit 1
    fi
    sleep 0.5
  done
  echo "Ready: ${name}"
}

poll_server "rust v1" 10001
poll_server "rust v2" 10002
poll_server "python async v1" 10101
poll_server "python async v2" 10102
poll_server "python sync v1" 10201
poll_server "python sync v2" 10202
poll_server "typescript v1" 10301
poll_server "typescript v2" 10302
poll_server "java v2" 10402
