#!/usr/bin/env sh
set -eu

repo="${1:-.}"
mkdir -p findings

semgrep scan --config auto --sarif --output findings/raw.sarif "$repo"
