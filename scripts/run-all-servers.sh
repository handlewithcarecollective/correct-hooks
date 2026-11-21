#!/usr/bin/env bash

# gcloud compute ssh $CORE_VM_INSTANCE_NAME --command="ps aux | grep \"[C]LOUDBURST_API_INSTANCE_ID $API_INSTANCE_ID\" | awk '{print \$2}' | xargs kill"

nohup "./scripts/individual-scripts/v1/rust-test-server.sh" > /dev/null 2>&1 &
nohup "./scripts/individual-scripts/v1/python-async-test-server.sh" > /dev/null 2>&1 &
nohup "./scripts/individual-scripts/v1/python-sync-test-server.sh" > /dev/null 2>&1 &
nohup "./scripts/individual-scripts/v1/typescript-test-server.sh" > /dev/null 2>&1 &

nohup "./scripts/individual-scripts/v2/rust-test-server.sh" > /dev/null 2>&1 &
# nohup "./scripts/individual-scripts/v2/python-async-test-server.sh" > /dev/null 2>&1 &
# nohup "./scripts/individual-scripts/v2/python-sync-test-server.sh" > /dev/null 2>&1 &
# nohup "./scripts/individual-scripts/v2/typescript-test-server.sh" > /dev/null 2>&1 &
