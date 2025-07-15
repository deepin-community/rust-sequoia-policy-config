A library for reading the configuration of [Sequoia]'s
`StandardPolicy` from a configuration file.

  [Sequoia]: https://sequoia-pgp.org
  [`StandardPolicy`]: https://docs.rs/sequoia-openpgp/1.11.0/sequoia_openpgp/policy/struct.StandardPolicy.html

Sequoia's [`StandardPolicy`] can be configured using Rust.  As with
most things, Sequoia's low-level library avoids imposing a policy on
users of the library, like where a configuration file should be or
even what format it should have.  When necessary, it is up to the
application to provide an interface, and to configure the policy
appropriately.

This library provides a high-level interface that parses a
configuration file, and returns a configured `StandardPolicy`.

See the crate's documentation for a description of the file format.

## Quick Start

To add `sequoia-policy-config` to your crate add the following your
crate:

```toml
[dependencies]
sequoia-openpgp = { version = "1" }
sequoia-policy-config = { version = "0.6" }
```

This will use `sequoia-openpgp`'s default cryptographic backend, which
is currently Nettle.

To select a different cryptographic backend, such as OpenSSL, you can
then do:

```shell
cargo build --release --no-default-features --features sequoia-openpgp/crypto-openssl
```

To use `sequoia-policy-config` in your crate, it is usually enough to
replace the use of `StandardPolicy::new` with the following::

```rust
use sequoia_policy_config::ConfiguredStandardPolicy;

fn main() -> openpgp::Result<()> {
    let mut p = ConfiguredStandardPolicy::new();
    p.from_bytes(b"[hash_algorithms]
        sha1.collision_resistance = \"never\"")?;
    let p = &p.build();

    // ...
    Ok(())
}
```

## Building

This crate is purely a library, so it is not usually built directly.
If you do build it (e.g., because you are modifying it), you'll need
to select a cryptographic backend.  See [`sequoia-openpgp`'s README]
for details.

  [`sequoia-openpgp`'s README]: https://gitlab.com/sequoia-pgp/sequoia#features

The short version is:

```
# Use the Nettle backend:
$ cargo build --release --features sequoia-openpgp/crypto-nettle
$ cargo test --release --features sequoia-openpgp/crypto-nettle

# Use the OpenSSL backend:
$ cargo build --release --features sequoia-openpgp/crypto-openssl
$ cargo test --release --features sequoia-openpgp/crypto-openssl
```

