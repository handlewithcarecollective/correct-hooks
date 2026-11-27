#!/usr/bin/env bash

mvn -q -f java/pom.xml package -DskipTests
java -jar java/test-server/target/test-server.jar --version v2 --port 10402
