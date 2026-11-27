#!/usr/bin/env bash

# Runs the Java test server on Java 8 (the library's baseline, no multi-release overrides).
# Set JAVA8_HOME to a Java 8 install; otherwise `java` from PATH is used.
# Run java-build.sh first.

JAVA="${JAVA8_HOME:+$JAVA8_HOME/bin/}java"
"$JAVA" -jar java/test-server/target/test-server.jar --version v2 --port 10402
