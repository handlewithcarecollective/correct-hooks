#!/usr/bin/env bash

# gcloud compute ssh $CORE_VM_INSTANCE_NAME --command="ps aux | grep \"[C]LOUDBURST_API_INSTANCE_ID $API_INSTANCE_ID\" | awk '{print \$2}' | xargs kill"

nohup "./scripts/individual-scripts/rust-test-server.sh" > /dev/null 2>&1 &
nohup "./scripts/individual-scripts/python-async-test-server.sh" > /dev/null 2>&1 &
nohup "./scripts/individual-scripts/python-sync-test-server.sh" > /dev/null 2>&1 &
nohup "./scripts/individual-scripts/typescript-test-server.sh" > /dev/null 2>&1 &
