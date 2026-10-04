# shellcheck shell=bash
# Sourced by bin/canaries: each canary plants a violation and
# expects a check to report it, by name. `failures` counts the canaries that
# went quiet; the sourcing script fails when it is above zero.
failures=0

fail() {
  echo "canary FAILED: $1"
  failures=$((failures + 1))
}

# expect_failure <name> <output-file> <command...>: the command must exit non-zero.
expect_failure() {
  local name="$1" out="$2"
  shift 2
  if "$@" >"$out" 2>&1; then
    fail "$name: the check passed a planted violation"
    return 1
  fi
}

# expect_reported <name> <output-file> <fixed-string...>: each string must appear.
expect_reported() {
  local name="$1" out="$2" pattern missing=0
  shift 2
  for pattern in "$@"; do
    if ! grep -qF -- "$pattern" "$out"; then
      fail "$name: expected the output to report: $pattern"
      missing=1
    fi
  done
  if [ "$missing" -eq 1 ]; then
    sed 's/^/    | /' "$out" | head -40
  else
    echo "canary ok: $name"
  fi
}

# expect_not_reported <name> <output-file> <fixed-string...>: none may appear,
# for the planted files a guard must leave alone.
expect_not_reported() {
  local name="$1" out="$2" pattern
  shift 2
  for pattern in "$@"; do
    if grep -qF -- "$pattern" "$out"; then
      fail "$name: reported what it must allow: $pattern"
    fi
  done
}
