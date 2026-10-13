#!/usr/bin/env bash
# Golden tests for the AI client collector: each case under tests/ai-scan/<case>
# holds a fake home, a fake filesystem root and the expected report. Any value
# containing CANARY in a fixture is a secret that must never reach the output.
# Set UPDATE_GOLDEN=1 to rewrite the expected files after a deliberate change.
set -euo pipefail
cd "$(dirname "$0")/.."
AGENT="$PWD/alfred-agent.sh"
failed=0

for case_dir in tests/ai-scan/*/; do
  name="$(basename "$case_dir")"
  work="$(mktemp -d)"
  cp -R "$case_dir"home "$case_dir"root "$work/"
  find "$work/home" -type f -exec perl -pi -e "s{\@HOME\@}{$work/home}g" {} +
  platform="linux"
  [ ! -f "${case_dir}platform" ] || platform="$(cat "${case_dir}platform")"
  actual="$(ALFRED_AI_SCAN_HOMES="$work/home" ALFRED_AI_SCAN_ROOT="$work/root" \
    ALFRED_AI_SCAN_PLATFORM="$platform" "$AGENT" ai-scan)"
  rm -rf "$work"
  if [ "${UPDATE_GOLDEN:-}" = "1" ]; then
    printf '%s\n' "$actual" >"${case_dir}expected.json"
  fi
  if grep -q CANARY <<<"$actual"; then
    echo "FAIL $name: a secret value leaked into the report" >&2
    grep -n CANARY <<<"$actual" >&2
    failed=1
  fi
  if grep -q "$work" <<<"$actual"; then
    echo "FAIL $name: the home directory path leaked into the report" >&2
    failed=1
  fi
  if ! diff -u "${case_dir}expected.json" <(printf '%s\n' "$actual"); then
    echo "FAIL $name: report differs from expected.json" >&2
    failed=1
  else
    echo "ok   $name"
  fi
done
exit "$failed"
