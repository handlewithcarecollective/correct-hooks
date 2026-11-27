#!/usr/bin/env bash

./scripts/kill-all-servers.sh

set -eu # exit on first error and on undefined variables.
./scripts/run-all-servers.sh

sleep 1

echo "!!! TESTING RUST V2"
./scripts/individual-scripts/v2/test-rust.sh
echo "!!! TESTING PYTHON ASYNC V2"
./scripts/individual-scripts/v2/test-python-async.sh
echo "!!! TESTING PYTHON SYNC V2"
./scripts/individual-scripts/v2/test-python-sync.sh
echo "!!! TESTING TYPESCRIPT V2"
./scripts/individual-scripts/v2/test-typescript.sh
echo "!!! TESTING JAVA V2"
./scripts/individual-scripts/v2/test-java.sh

echo "!!! TESTING RUST V1"
./scripts/individual-scripts/v1/test-rust.sh
echo "!!! TESTING PYTHON ASYNC V1"
./scripts/individual-scripts/v1/test-python-async.sh
echo "!!! TESTING PYTHON SYNC V1"
./scripts/individual-scripts/v1/test-python-sync.sh
echo "!!! TESTING TYPESCRIPT V1"
./scripts/individual-scripts/v1/test-typescript.sh

./scripts/kill-all-servers.sh
