#!/usr/bin/env bash

kill "$(lsof -ti :4500)"
kill "$(lsof -ti :4501)"
kill "$(lsof -ti :4502)"
kill "$(lsof -ti :4503)"
