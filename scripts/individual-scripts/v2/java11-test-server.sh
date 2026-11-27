#!/usr/bin/env bash

# Runs the Java test server on Java 11 (uses the multi-release jar's Java 11 overrides).
# Set JAVA11_HOME to a Java 11 install; otherwise `java` from PATH is used.
# Run java-build.sh first.

JAVA="${JAVA11_HOME:+$JAVA11_HOME/bin/}java"
"$JAVA" -jar java/test-server/target/test-server.jar --version v2 --port 10502
