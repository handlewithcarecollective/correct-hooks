#!/usr/bin/env bash

cargo fix --allow-dirty
cargo +nightly fmt

uv run ruff check --fix
uv run ruff format

yarn --cwd typescript/correct-hooks run lint:fix
yarn --cwd typescript/correct-hooks run fmt