# shellcheck shell=bash
# Sourced by the bin/ scripts. When mise is installed, put the pinned
# toolchain (mise.toml, rust-toolchain.toml) first on PATH. Without mise, the
# tools already on PATH are used and `bin/guard toolchain` checks they match
# the pins.
if command -v mise >/dev/null 2>&1; then
  eval "$(mise env --shell bash)"
fi

step() {
  printf '\n==> %s\n' "$*"
}

# The oldest Rust the crate supports: `rust-version` in Cargo.toml, its only
# source.
msrv() {
  sed -n 's/^rust-version = "\(.*\)"$/\1/p' Cargo.toml
}

# clippy [args...]: clippy over the crate, its tests and the fuzz target,
# never the planted violations in guards/rust-canary, which only
# bin/canaries lints.
clippy() {
  cargo clippy -p spake2plus -p spake2plus-fuzz --all-targets --locked "$@"
}
