# spake2plus: instructions for agents

A Rust crate implementing SPAKE2+ (RFC 9383), published on crates.io under
the MIT license. `README.md` is for using it (and is the crate's rustdoc);
this file is for changing it.

## Before you branch

- Branch from a fresh `origin/main`: `git fetch origin && git switch -c <branch> origin/main`.
- Agents open pull requests; the owner merges and publishes. Never merge,
  never push to `main`, never `git stash`, never `cargo publish` (only
  `cargo publish --dry-run`).
- After cloning: `bin/setup`.

## Commands

| Command | What it does |
|---|---|
| `bin/check` | The read-only gate. Fails on any finding, warnings included. Never writes. |
| `bin/test` | Every test once, in the foreground, then `bin/canaries`. |
| `bin/fix` | The only writer: safe lint fixes and formatting. Never use it to verify. |
| `bin/guard <name>` | One repo-wide guard (the script header lists them). |
| `cargo deny check advisories` | Known vulnerabilities; advisory, outside the gate. |

The `bin/` scripts load the pinned toolchain with `mise env`; a bare `cargo`
may be another Rust. Use the scripts or `mise exec -- <command>`.

## Definition of done

1. `bin/check && bin/test` green, run in the foreground with exit codes read
   directly. Report the test counts before and after, with the command.
2. Tests match the change: a feature has tests; a bug fix has a regression
   test that fails on the parent commit. Protocol code (the transcript, the
   key schedule, confirmation checks, point validation) is checked against
   RFC 9383's vectors, and each check is proved to bite by breaking it once.
3. New code passes lint outright: no new suppressions without a reason, no
   raised ceilings.
4. `CHANGELOG.md` records every change a user of the crate can see.

## Rules

- **Warnings fail.** Lints live in `[workspace.lints]` in `Cargo.toml`
  (pedantic on), size ceilings in `clippy.toml`. Suppress only with
  `#[expect(lint, reason = "...")]`; `#[allow]` is rejected.
- **Lint configs exist only at** `clippy.toml` and `deny.toml`
  (`bin/guard lint-configs`). No baseline or ignore files.
- **No em-dashes or en-dashes** anywhere in the repo (`bin/guard em-dashes`),
  nor in commit messages or pull request text.
- **Every guard proves it can fail** with a planted violation in
  `bin/canaries` (`guards/rust-canary` for the lint config).
- **The library never panics on its caller's input**: `unwrap`, `expect`,
  `panic!` and indexing are lints outside tests.
- **`no_std` without `alloc`.** `bin/check` builds the crate for a target
  without `std` and on the oldest supported Rust (`rust-version`, its only
  source).
- **Secrets are zeroized on drop and never shown by `Debug`.** Compare
  anything secret in constant time (`subtle`).
- **`Suite` and `Bytes` stay sealed**, so suites and trait items can be added
  without a breaking release. Public API changes follow semver.
- **New dependencies or tools need the owner's approval**, with exact pins.
- Never copy GPL code. Prior art (RFC 9383, the MIT `tapo` crate, RustCrypto's
  `spake2`) is for ideas only.

## Layout

- `src/suite.rs`: the sealed `Suite` and the group operations per suite.
- `src/registration.rs`, `src/messages.rs`: what the sides hold and send.
- `src/prover.rs`, `src/verifier.rs`: the two roles, as consuming states.
- `src/schedule.rs`: the transcript and the key schedule.
- `src/tests/`: RFC 9383's vectors, value by value; `tests/`: the public API.
- `fuzz/`: the cargo-fuzz target (README, Contributing).

## Maintaining this file

- Write the rule, not its history.
- When you add something, look for something to delete.
