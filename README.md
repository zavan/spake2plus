# spake2plus

SPAKE2+ ([RFC 9383]) in Rust: the augmented password-authenticated key
exchange, with both roles, `no_std` and without `alloc`.

A client (the **prover**, which knows the password) and a server (the
**verifier**, which stores only a record derived from it) agree on a shared
key over an untrusted channel, and each proves to the other that it holds the
password or its record. Nothing on the wire lets an eavesdropper test
password guesses, an active attacker gets one guess per run, and someone who
steals the server's records must still guess each password before posing as
its client.

Use it where a password (or a PIN, or a setup code) is the only secret the two
sides share and the server should not hold the password itself: device
pairing and logins to local devices; TP-Link's TPAP, for one, is built on
it. If both sides hold the same secret, the
symmetric SPAKE2 ([RFC 9382], the [`spake2`] crate) is enough.

## Example

```rust
use spake2plus::{Context, P256Sha256, Prover, ProverSecret, Verifier};

fn main() -> Result<(), spake2plus::Error> {
    // Registration: the prover's secret from its password hash's output (see
    // below), and the record the verifier stores.
    let pbkdf_output = [7; 80]; // stands in for the password hash's output
    let secret = ProverSecret::<P256Sha256>::from_pbkdf_output(&pbkdf_output)?;
    let record = secret.verifier_record();

    // Both sides bind the same context and identities into the run.
    let context = Context {
        context: b"MyApp v1",
        prover_id: b"alice",
        verifier_id: b"server",
    };
    let mut rng = rand::rng();

    // Prover -> verifier: shareP.
    let (prover, share_p) = Prover::start(&secret, &context, &mut rng);

    // Verifier -> prover: shareV and confirmV.
    let (verifier, share_v) = Verifier::start(&record, &context, &mut rng);
    let (verifier, confirm_v) = verifier.receive(&share_p)?;

    // The prover checks confirmV, then sends confirmP.
    let (confirm_p, prover_key) = prover.receive(&share_v)?.finish(&confirm_v)?;

    // The verifier checks confirmP.
    let verifier_key = verifier.finish(&confirm_p)?;
    assert_eq!(prover_key.as_bytes(), verifier_key.as_bytes());
    Ok(())
}
```

Every message has `as_bytes()` to send and `from_bytes()` to parse what the
peer sent. Each step consumes its session, so a run cannot be repeated or
confirmed twice, and the `SharedKey` exists only once the peer's
confirmation has been checked. Derive the application's keys from it, for
example with HKDF.

### Registration: the password hash is yours

RFC 9383 leaves the password hash to the application. Run a slow, salted
password hash (Argon2id or scrypt are the RFC's examples) over

```text
len(pw) || pw || len(idProver) || idProver || len(idVerifier) || idVerifier
```

(each `len` eight bytes, little-endian), and pass its output, at least 80
bytes for P-256, to `ProverSecret::from_pbkdf_output`. The [crate
documentation][docs] shows it with PBKDF2. The verifier stores
`secret.verifier_record().to_bytes()` and never the password or the
`ProverSecret`.

### Confirming first

RFC 9383 has the prover check the verifier's confirmation before sending its
own. Some protocols (TP-Link's TPAP among them) send the prover's
confirmation first; `ProverConfirming::confirm_first()` does that. It lets an
impostor posing as the verifier test password guesses offline against the
prover's confirmation, so use it only when the protocol forces that order,
and with a slow password hash.

## Suites

| Suite | Group | Hash, KDF, MAC |
|---|---|---|
| `P256Sha256` | P-256 | SHA-256, HKDF-SHA256, HMAC-SHA256 |
| `P256Sha512` | P-256 | SHA-512, HKDF-SHA512, HMAC-SHA512 |

Both pass every value of RFC 9383's test vectors for them, in both roles. The
`Suite` trait is sealed, so the RFC's other suites can be added without
breaking callers.

## Security

- **No audit.** This code has not been reviewed by a third party. It follows
  the RFC and is tested against its vectors, but treat it accordingly.
- **Constant time.** Scalar multiplication is the `p256` crate's, which is
  constant time, and confirmations are compared in constant time
  (`subtle`). Not constant time, by design: parsing and validating shares,
  records and lengths, which only handle public data, and the check that a
  share does not cancel the password's mask, whose outcome ends the run
  anyway.
- **Validation.** A share must be an uncompressed SEC1 point on the curve and
  not the identity, or it does not parse. A share equal to the password's
  mask (`w0*N` from a verifier, `w0*M` from a prover) is refused, since it
  would leave nothing secret in the key.
- **Zeroization.** The prover's secret, the verifier's record, every session
  and the shared key are zeroized on drop (`zeroize`), and so are the hash
  and HMAC states (the `zeroize` features of `sha2` and `hmac`). Copies the
  compiler makes when values move, and bytes the caller copies out, are
  beyond its reach.
- **Randomness.** The ephemeral scalars come from the `CryptoRng` the caller
  passes (`spake2plus::rand_core` re-exports the version this crate takes),
  so it must be a cryptographically secure one, such as `rand::rng()`.

## Minimum supported Rust

1.85 (`rust-version` in `Cargo.toml`).

## Contributing

`bin/setup` installs the pinned tools through [mise] (`mise.toml`, with Rust
pinned in `rust-toolchain.toml`), the pinned toolchain's `no_std` target, and,
through rustup, the oldest supported Rust that `rust-version` in
`Cargo.toml` names. Then:

| Command | What it does |
|---|---|
| `bin/check` | The read-only gate: guards, shellcheck, rustfmt, clippy, rustdoc, the oldest supported Rust, unused dependencies, licenses. |
| `bin/test` | Every test once, then the canaries that prove each check can fail. |
| `bin/fix` | Safe lint fixes and formatting. |
| `cargo deny check advisories` | Known vulnerabilities in the dependencies, from an outside database, so not part of the gate. |

The fuzz target parses every kind of message and runs the steps that take
them. It needs [cargo-fuzz] 0.13.2 and a nightly toolchain:

```sh
cargo install cargo-fuzz --version 0.13.2 --locked
rustup toolchain install nightly
cargo +nightly fuzz run parse_messages
```

## License

MIT: see `LICENSE`.

[RFC 9383]: https://www.rfc-editor.org/rfc/rfc9383
[RFC 9382]: https://www.rfc-editor.org/rfc/rfc9382
[`spake2`]: https://crates.io/crates/spake2
[docs]: https://docs.rs/spake2plus
[mise]: https://mise.jdx.dev
[cargo-fuzz]: https://github.com/rust-fuzz/cargo-fuzz
