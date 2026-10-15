#!/usr/bin/env bash

./scripts/kill-all-servers.sh

set -eu # exit on first error and on undefined variables.
./scripts/run-all-servers.sh

sleep 1

echo "!!! TESTING RUST"
./scripts/individual-scripts/test-rust.sh
echo "!!! TESTING PYTHON ASYNC"
./scripts/individual-scripts/test-python-async.sh
echo "!!! TESTING PYTHON SYNC"
./scripts/individual-scripts/test-python-sync.sh
echo "!!! TESTING TYPESCRIPT"
./scripts/individual-scripts/test-typescript.sh

./scripts/kill-all-servers.sh
