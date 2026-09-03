#!/usr/bin/env sh
set -eu

# Rules come from a local directory by default. docs/03-data-handling.md
# claims exactly one channel out of the perimeter — the review packet — and
# `--config auto` quietly opened a second one by fetching rules from the
# Semgrep registry and reporting telemetry. Going to the registry is still
# possible, but it is now a decision someone makes out loud.

repo="${1:-.}"
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
config="${SEMGREP_CONFIG:-$root/rules}"

# Resolution happens before semgrep is invoked so the refusal path works on a
# machine without semgrep, and so it can be tested there too. Nothing is
# created on disk until the configuration is known to be usable: a refusal
# that leaves state behind is not a clean refusal.
case "$config" in
  p/*|r/*|https://*)
    printf 'NETWORK: fetching rules from the Semgrep registry (%s).\n' "$config" >&2
    printf 'This is a second channel out of the perimeter.\n' >&2
    printf 'See docs/03-data-handling.md.\n\n' >&2
    ;;
  *)
    if [ ! -d "$config" ] || [ -z "$(ls -A "$config" 2>/dev/null | grep -v '^README.md$' || true)" ]; then
      printf 'REFUSED: no local rules in %s\n\n' "$config" >&2
      printf 'Add Semgrep rule files for this repository, or opt into the\n' >&2
      printf 'registry explicitly:\n\n' >&2
      printf '    SEMGREP_CONFIG=p/security-audit make scan REPO=%s\n\n' "$repo" >&2
      printf 'docs/03-data-handling.md explains why the default is offline.\n' >&2
      exit 2
    fi
    ;;
esac

mkdir -p findings

printf 'Rules:  %s\n' "$config"
printf 'Target: %s\n\n' "$repo"

semgrep scan --config "$config" --metrics=off --sarif \
  --output findings/raw.sarif "$repo"
