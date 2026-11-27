#!/usr/bin/env bash

kill "$(lsof -ti :10001)"
kill "$(lsof -ti :10002)"
kill "$(lsof -ti :10101)"
kill "$(lsof -ti :10102)"
kill "$(lsof -ti :10201)"
kill "$(lsof -ti :10202)"
kill "$(lsof -ti :10301)"
kill "$(lsof -ti :10302)"
kill "$(lsof -ti :10402)"
kill "$(lsof -ti :10502)"
