#!/usr/bin/env bash

./scripts/kill-all-servers.sh

set -eu # exit on first error and on undefined variables.
./scripts/run-all-servers.sh

sleep 1

echo "!!! TESTING RUST"
./scripts/individual-scripts/v1/test-rust.sh
echo "!!! TESTING PYTHON ASYNC"
./scripts/individual-scripts/v1/test-python-async.sh
echo "!!! TESTING PYTHON SYNC"
./scripts/individual-scripts/v1/test-python-sync.sh
echo "!!! TESTING TYPESCRIPT"
./scripts/individual-scripts/v1/test-typescript.sh

./scripts/kill-all-servers.sh
