//! Configures a `StandardPolicy` using a configuration file.
//!
//! Sequoia's [`StandardPolicy`] can be configured using Rust.  As
//! with most things, Sequoia's low-level library avoids imposing a
//! policy on users of the library, like where a configuration file
//! should be or even what format it should have.  When necessary, it
//! is up to the application to provide an interface, and to configure
//! the policy appropriately.
//!
//! [`StandardPolicy`]: https://docs.rs/sequoia-openpgp/1.*/sequoia_openpgp/policy/struct.StandardPolicy.html
//!
//! This library provides a high-level interface that parses a
//! configuration file, and returns a configured `StandardPolicy`.
//!
//! # Format
//!
//! The file format is based on [TOML].  It contains several sections,
//! one for hash algorithms, one for asymmetric algorithms, etc.
//!
//! [TOML]: https://toml.io/
//!
//! ## Forward Compatibility
//!
//! This parser is strict, but we want the configuration format to be
//! forwards compatible so that the same configuration file can be
//! used with different versions of the parser.
//!
//! ### Dealing with New Keys
//!
//! Unknown sections and unknown keys cause a parse error.  To allow
//! configuration files a degree of backwards compatibility, it is
//! possible to set the per-map `ignore_invalid` key to the key or the
//! list of keys that should be ignored if they are not recognized.
//! For instance, if Sequoia adds support for `SHA4`, then you could
//! do the following to unconditionally reject `SHA4` while ensuring
//! that the configuration is still readable by older versions of
//! Sequoia that don't know about `SHA4`:
//!
//! ```toml
//! [hash_algorithms]
//! ignore_invalid = [ "sha4" ]
//! sha4 = never
//! ```
//!
//! (The same principle applies to sections.)
//!
//! ### Dealing with Type Changes
//!
//! Most keys are string types.  In the future, we may want to make a
//! given algorithm or data structure's configuration more nuanced.  A
//! logical way to do this is to change the key from taking a string
//! type to taking a map type.
//!
//! To support this type of change, all keys that take a string are
//! also recognized as maps with a single key, `default_disposition`.
//! Thus, if `key` is ever extended in this way,
//! `key.default_disposition` can be used to control the configuration
//! of older versions, and new versions can use the configuration
//! parameters.
//!
//! For instance, imagine that AES128 is found to be vulnerable to an
//! attack called `foo` in certain, detectable situations.  We could
//! extend AES128 with a new key (`foo`) that is respected when those
//! conditions are detected.  This can be expressed in the following,
//! backwards compatible manner:
//!
//! ```toml
//! [symmetric_algorithms]
//! aes128.default_disposition = "always"
//! aes128.foo = "2023-01-01"
//! aes128.ignore_invalid = "foo"
//! ```
//!
//! ## Cutoff Times
//!
//! Most settings take a so-called cutoff time.  The cutoff time is
//! the time at which an algorithm (e.g., the broken [SHA-1] hash
//! algorithm) or a data structure (e.g. the obsolete [SED packet])
//! should no longer be considered valid.  Using a cutoff time
//! provides more nuance than simply marking an algorithm as invalid.
//! In particular, it allows sun setting algorithms that have been
//! weakened, but are not yet completely broken, and using data that
//! has been saved to a trusted medium before its security was broken.
//!
//! Cutoff times are expressed using TOML's `datetime` datatype, which
//! is an [RFC 3339] formatted timestamp.  The following variants are
//! valid:
//!
//! [SHA-1]: https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-crypto-refresh-07#section-14.1
//! [SED packet]: https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-crypto-refresh-07#section-5.7
//!
//! Offset datetime:
//!
//! ```toml
//! [hash_algorithms]
//! sha1 = 2010-01-01T00:00:00Z
//! ```
//!
//! Local datetime:
//!
//! ```toml
//! [hash_algorithms]
//! sha1 = 2010-01-01T00:00:00+00:00
//! ```
//!
//! Local date (interpreted as midnight in UTC):
//!
//! ```toml
//! [hash_algorithms]
//! sha1 = 2010-01-01
//! ```
//!
//! The local time format is not supported as it doesn't make sense in
//! this context.
//!
//! [RFC 3339]: https://www.rfc-editor.org/rfc/rfc3339
//!
//! Two special values are also supported: `always` means that the
//! algorithm or data structure should always be considered valid, and
//! `never` means that the algorithm or data structure should never be
//! considered valid.  These values are checked for in a
//! case-sensitive manner.
//!
//! ```toml
//! [hash_algorithms]
//! sha1 = "never"
//! ```
//!
//! ## Default Disposition
//!
//! In some situations, it is desirable to only allow a fixed set of
//! algorithms.  Using the cutoff mechanism, it is possible to accept
//! or reject each of the known algorithms, but unknown algorithms,
//! i.e., those that Sequoia will add in the future, and will likely
//! enable by default, can't be rejected in this way, because their
//! name is---by definition---not yet known.
//!
//! To accommodate this usage, it is possible to set an algorithm
//! class or data structure class's default disposition using the
//! `default_disposition` key.  Currently, only one value is supported
//! for this key: `never`.  If this key is present in a section, then
//! that key is processed first, and all algorithms are set to be
//! rejected.  The rest of the keys are then processed as usual.
//!
//! The following example shows how to only allow the SHA256 and
//! SHA512 hash functions.  Even if a theoretical SHA4 hash function
//! is added to Sequoia, it will be rejected by this configuration.
//!
//! ```toml
//! [hash_algorithms]
//! sha256.collision_resistance = "always"
//! sha256.second_preimage_resistance = "always"
//! sha512.collision_resistance = "always"
//! sha512.second_preimage_resistance = "always"
//! default_disposition = "never"
//! ```
//!
//! ## Sections
//!
//! ### Hash Functions
//!
//! Hash algorithms are used to ensure multiple properties.  Of
//! particular relevance in the context of OpenPGP are collision
//! resistance, and second preimage resistance.  In some contexts like
//! self signatures, only second preimage resistance is required.  In
//! other contexts, both properties are required.  As collision
//! resistance is much easier to attack, these two properties can be
//! set separately.
//!
//! You configure just the second preimage resistance cutoff by
//! setting the `ALGO.second_preimage_resistance` key.  You configure
//! just the collision resistance cutoff by setting the
//! `ALGO.collision_resistance` key.  Setting the `ALGO` key is
//! shorthand for setting both.
//!
//! A hash algorithm's key is the lower-case version of the value
//! returned by the [`Display` name][hash-display].  For instance,
//! SHA1 is `sha1`.
//!
//! [hash-display]: https://docs.rs/sequoia-openpgp/1.10.0/sequoia_openpgp/types/enum.HashAlgorithm.html#impl-Display
//!
//! ```toml
//! [hash_algorithms]
//! md5 = "never"
//! sha1.second_preimage_resistance = 2030-01-01
//! sha1.collision_resistance = 2022-01-01
//! sha512 = "always"
//! ```
//!
//! ### Symmetric Algorithms
//!
//! Like hash algorithms, [symmetric algorithms] can be rejected
//! outright or have a cutoff date.  They don't have any subkeys like
//! `collision_resistance`, so there is only one way to set the
//! cutoff: using the `algo` key.
//!
//! [symmetric algorithms]: https://docs.rs/sequoia-openpgp/1.10.0/sequoia_openpgp/types/enum.SymmetricAlgorithm.html#impl-Display
//!
//! The unencrypted variant, the unknown variants, and the private
//! variants cannot currently be set.
//!
//! ```toml
//! [symmetric_algorithms]
//! cast5 = "never"
//! aes128 = "always"
//! ```
//!
//! ### Asymmetric Algorithms
//!
//! Like symmetric algorithms, [asymmetric algorithms] can be rejected
//! outright or have a cutoff date.
//!
//! [asymmetric algorithms]: https://docs.sequoia-pgp.org/sequoia_openpgp/policy/enum.AsymmetricAlgorithm.html#impl-Display
//!
//! The unknown variants, and the private variants cannot currently be
//! set.
//!
//! ```toml
//! [asymmetric_algorithms]
//! rsa1024 = "never"
//! rsa2048 = 2028-01-01
//! ```
//!
//! ### AEAD Algorithms
//!
//! Like symmetric algorithms, [AEAD algorithms] can be rejected
//! outright or have a cutoff date.
//!
//! [AEAD algorithms]: https://docs.rs/sequoia-openpgp/1.10.0/sequoia_openpgp/types/enum.AEADAlgorithm.html#impl-Display
//!
//! The unknown variants, and the private variants cannot currently be
//! set.
//!
//! ```toml
//! [aead_algorithms]
//! eax = "never"
//! ocb = "always"
//! ```
//!
//! ### Packets
//!
//! Packets can be rejected outright or have a cutoff date.  The [SED
//! packet] is, for instance, considered broken, and messages that use
//! it should generally be rejected unless they are known to not be
//! from an attacker, e.g., because they were stored on a trusted
//! medium before the attack was feasible.
//!
//! It is also possible to reject particular versions of a packet.  In
//! this case, the packet is a map and the fields `vX` where `X` is a
//! `u8` can be used to set the cutoff for version `X` of the packet.
//! This mechanism is only supported for packets that actually are
//! versioned, and only for known versions.  (Unknown versions can
//! still be set in a forwards compatible way using the
//! `ignore_invalid` key.)
//!
//! The packets are named after the [names of the Packet variants].
//!
//! [names of the Packet variants]: https://docs.rs/sequoia-openpgp/1.10.0/sequoia_openpgp/packet/enum.Tag.html#variants
//!
//! The reserved packet, the unknown variants, and the private
//! variants cannot currently be set.
//!
//! ```toml
//! [packets]
//! sed = "never"
//! seip = 2028-01-01
//!
//! signature.v3 = 2017-01-01
//! signature.v4 = 2030-01-01
//! signature.v6 = "always"
//! # v6 signatures are coming, but not yet recognized.
//! signature.ignore_invalid = "v6"
//! ```
//!
//! ## Examples
//!
//! The following example shows how to use a configuration file to
//! configure a `StandardPolicy`:
//!
//! ```rust
//! use sequoia_openpgp as openpgp;
//! use openpgp::policy::HashAlgoSecurity;
//! use openpgp::types::HashAlgorithm;
//!
//! use sequoia_policy_config::ConfiguredStandardPolicy;
//!
//! # fn main() -> openpgp::Result<()> {
//! let mut p = ConfiguredStandardPolicy::new();
//! p.parse_bytes(b"[hash_algorithms]
//!     sha1.collision_resistance = \"never\"")?;
//! let p = &p.build();
//!
//! assert_eq!(p.hash_cutoff(HashAlgorithm::SHA1,
//!                          HashAlgoSecurity::CollisionResistance),
//!            Some(std::time::UNIX_EPOCH));
//! # Ok(()) }
//! ```

#![allow(clippy::type_complexity)]

use std::collections::HashSet;
use std::env;
use std::io;
use std::path::Path;
use std::path::PathBuf;
use std::string::String;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use sequoia_openpgp as openpgp;
use openpgp::packet::Tag;
use openpgp::policy::AsymmetricAlgorithm;
use openpgp::policy::StandardPolicy;
use openpgp::policy::HashAlgoSecurity;
use openpgp::types::AEADAlgorithm;
use openpgp::types::HashAlgorithm;
use openpgp::types::SymmetricAlgorithm;

use anyhow::Context as _;

use chrono::DateTime;
use chrono::NaiveDate;
use chrono::Utc;

use toml::value;
use toml::Value;

mod dump;
pub use dump::DumpDefault;
#[cfg(test)]
mod testdata;

#[derive(Clone, Debug)]
pub struct ConfiguredStandardPolicy<'a> {
    policy: StandardPolicy<'a>,
}

type Result<T, E=anyhow::Error> = std::result::Result<T, E>;

/// Errors used in this crate.
///
/// Note: This enum cannot be exhaustively matched to allow future
/// extensions.
#[non_exhaustive]
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Parse error
    #[error("Parse error: {0}")]
    ParseError(String),

    /// A Relative Path was provided where an absolute path was expected.
    #[error("Relative path not allowed: {0}")]
    RelativePathError(PathBuf),

    /// An algorithm is not known to this crate.
    #[error("Unknown algorithm: {0}")]
    UnknownAlgorithm(String),
}

/// A timestamp.
///
/// None is always.
type Timestamp = Option<SystemTime>;

/// Always accept.
const ALWAYS: Timestamp = None;

/// Never accept.
///
/// By setting the acceptance time to the unix epoch, we never accept
/// anything.
const NEVER: Timestamp = Some(UNIX_EPOCH);

// Parses a timestamp stored in a toml value.
//
// Recognizes the special values "always" and "never".
fn parse_time(t: &Value) -> Result<Timestamp> {
    let t = match t {
        Value::String(t) => t.clone(),
        Value::Datetime(t) => t.to_string(),
        _ => Err(Error::ParseError(
            format!("timestamp is not a string ({:?})", t)))?,
    };

    Ok(match &t[..] {
        "always" => ALWAYS,
        "never" => NEVER,
        t => {
            let t = if let Ok(p) = DateTime::parse_from_rfc3339(t) {
                p.into()
            } else {
                let t = NaiveDate::parse_from_str(t, "%Y-%m-%d")
                    .context(format!("Parsing timestamp {}", t))?
                    .and_hms_opt(0, 0, 0).expect("valid time");
                let t: DateTime<Utc> = DateTime::from_utc(t, Utc);
                t.into()
            };

            Some(t)
        }
    })
}

// Returns an error if a key is unknown.
//
// known_keys better be lowercase.
fn check_sections(path: Option<&str>,
                  section: &value::Map<String, Value>,
                  known_keys: &[&str]) -> Result<()> {
    // known_keys better be lowercase.
    known_keys.iter().for_each(
        |&s| debug_assert_eq!(&s.to_lowercase()[..], s));

    let prefix = || if let Some(path) = path {
        format!("{}.", path)
    } else {
        "".to_string()
    };

    let keys: HashSet<&str> = section
        .keys()
        .map(|s| s.as_str())
        .collect();

    // The set of allowed keys are the known keys, plus
    // "ignore_invalid", and the value of "ignore_invalid".
    let mut allowed_keys: Vec<&str> = known_keys.to_vec();
    if let Some(ignore) = section.get("ignore_invalid") {
        allowed_keys.push("ignore_invalid");
        match ignore {
            Value::String(k) => allowed_keys.push(k.as_str()),
            Value::Array(ks) => {
                for k in ks {
                    if let Value::String(k) = k {
                        allowed_keys.push(k.as_str());
                    } else {
                        Err(Error::ParseError(format!(
                            "'{}ignore_invalid' takes a string \
                             or an array of strings",
                            prefix())))?
                    }
                }
            }
            _ => {
                return Err(Error::ParseError(format!(
                    "Invalid value for '{}ignore_invalid': {}, \
                     expected a string or an array of strings",
                    prefix(), ignore)).into());
            }
        }
    }

    // Now check if there are any unknown sections.
    let unknown_keys = keys
        .difference(&allowed_keys.into_iter().collect())
        .map(|s| *s)
        .collect::<Vec<_>>();
    if ! unknown_keys.is_empty() {
        return Err(Error::ParseError(format!(
            "{} has unknown keys: {}, valid keys are: {}",
            if let Some(path) = path {
                path
            } else {
                "top-level section"
            },
            unknown_keys.join(", "),
            // We don't include the keys listed in ignore_invalid.
            known_keys.join(", "))).into());
    }

    Ok(())
}

const HASH_ALGO_PROPS: &[(&str, HashAlgoSecurity)] = &[
    ("second_preimage_resistance", HashAlgoSecurity::SecondPreImageResistance),
    ("collision_resistance", HashAlgoSecurity::CollisionResistance),
];

const HASH_ALGO_MAP: [(&str, HashAlgorithm, &[(&str, HashAlgoSecurity)]); 9] = [
    ("md5", HashAlgorithm::MD5, HASH_ALGO_PROPS),
    ("sha1", HashAlgorithm::SHA1, HASH_ALGO_PROPS),
    ("ripemd160", HashAlgorithm::RipeMD, HASH_ALGO_PROPS),
    ("sha256", HashAlgorithm::SHA256, HASH_ALGO_PROPS),
    ("sha384", HashAlgorithm::SHA384, HASH_ALGO_PROPS),
    ("sha512", HashAlgorithm::SHA512, HASH_ALGO_PROPS),
    ("sha224", HashAlgorithm::SHA224, HASH_ALGO_PROPS),
    ("sha3-256", HashAlgorithm::SHA3_256, HASH_ALGO_PROPS),
    ("sha3-512", HashAlgorithm::SHA3_512, HASH_ALGO_PROPS),
];

const ASYMM_ALGO_MAP: [(&str, AsymmetricAlgorithm, &[(&str, ())]); 23] = [
    ("rsa1024", AsymmetricAlgorithm::RSA1024, &[]),
    ("rsa2048", AsymmetricAlgorithm::RSA2048, &[]),
    ("rsa3072", AsymmetricAlgorithm::RSA3072, &[]),
    ("rsa4096", AsymmetricAlgorithm::RSA4096, &[]),
    ("elgamal1024", AsymmetricAlgorithm::ElGamal1024, &[]),
    ("elgamal2048", AsymmetricAlgorithm::ElGamal2048, &[]),
    ("elgamal3072", AsymmetricAlgorithm::ElGamal3072, &[]),
    ("elgamal4096", AsymmetricAlgorithm::ElGamal4096, &[]),
    ("dsa1024", AsymmetricAlgorithm::DSA1024, &[]),
    ("dsa2048", AsymmetricAlgorithm::DSA2048, &[]),
    ("dsa3072", AsymmetricAlgorithm::DSA3072, &[]),
    ("dsa4096", AsymmetricAlgorithm::DSA4096, &[]),
    ("nistp256", AsymmetricAlgorithm::NistP256, &[]),
    ("nistp384", AsymmetricAlgorithm::NistP384, &[]),
    ("nistp521", AsymmetricAlgorithm::NistP521, &[]),
    ("brainpoolp256", AsymmetricAlgorithm::BrainpoolP256, &[]),
    ("brainpoolp384", AsymmetricAlgorithm::BrainpoolP384, &[]),
    ("brainpoolp512", AsymmetricAlgorithm::BrainpoolP512, &[]),
    ("cv25519", AsymmetricAlgorithm::Cv25519, &[]),
    ("x25519", AsymmetricAlgorithm::X25519, &[]),
    ("ed25519", AsymmetricAlgorithm::Ed25519, &[]),
    ("x448", AsymmetricAlgorithm::X448, &[]),
    ("ed448", AsymmetricAlgorithm::Ed448, &[]),
];

#[allow(deprecated)]
const SYMM_ALGO_MAP: [(&str, SymmetricAlgorithm, &[(&str, ())]); 11] = [
    ("idea", SymmetricAlgorithm::IDEA, &[]),
    ("tripledes", SymmetricAlgorithm::TripleDES, &[]),
    ("cast5", SymmetricAlgorithm::CAST5, &[]),
    ("blowfish", SymmetricAlgorithm::Blowfish, &[]),
    ("aes128", SymmetricAlgorithm::AES128, &[]),
    ("aes192", SymmetricAlgorithm::AES192, &[]),
    ("aes256", SymmetricAlgorithm::AES256, &[]),
    ("twofish", SymmetricAlgorithm::Twofish, &[]),
    ("camellia128", SymmetricAlgorithm::Camellia128, &[]),
    ("camellia192", SymmetricAlgorithm::Camellia192, &[]),
    ("camellia256", SymmetricAlgorithm::Camellia256, &[]),
];

const AEAD_ALGO_MAP: [(&str, AEADAlgorithm, &[(&str, ())]); 3] = [
    ("eax", AEADAlgorithm::EAX, &[]),
    ("ocb", AEADAlgorithm::OCB, &[]),
    ("gcm", AEADAlgorithm::GCM, &[]),
];

const PACKET_MAP: [(&str, Tag, &[(&str, u8)]); 19] = [
    ("pkesk", Tag::PKESK, &[("v3", 3), ("v5", 5), ("v6", 6)]),
    ("signature", Tag::Signature, &[("v3", 3), ("v4", 4), ("v5", 5), ("v6", 6)]),
    ("skesk", Tag::SKESK, &[("v4", 4), ("v5", 5), ("v6", 6)]),
    ("onepasssig", Tag::OnePassSig, &[("v3", 3), ("v6", 6)]),
    ("secretkey", Tag::SecretKey, &[("v4", 4), ("v5", 5), ("v6", 6)]),
    ("publickey", Tag::PublicKey, &[("v4", 4), ("v5", 5), ("v6", 6)]),
    ("secretsubkey", Tag::SecretSubkey, &[("v4", 4), ("v5", 5), ("v6", 6)]),
    ("compresseddata", Tag::CompressedData, &[]),
    ("sed", Tag::SED, &[]),
    ("marker", Tag::Marker, &[]),
    ("literal", Tag::Literal, &[]),
    ("trust", Tag::Trust, &[]),
    ("userid", Tag::UserID, &[]),
    ("publicsubkey", Tag::PublicSubkey, &[("v4", 4), ("v5", 5), ("v6", 6)]),
    ("userattribute", Tag::UserAttribute, &[]),
    ("seip", Tag::SEIP, &[("v1", 1), ("v2", 2)]),
    ("mdc", Tag::MDC, &[]),
    ("aed", Tag::AED, &[("v1", 1)]),
    ("padding", Tag::Padding, &[]),
];

/// Given a map and an algorithm (or packet tag), returns the key
/// usable in the configuration file.
fn algo_to_key<A, V>(map: &[(&'static str, A, &[V])], a: A)
                     -> std::result::Result<&'static str, Error>
where
    A: Copy + PartialEq + ToString,
{
    map.iter().find_map(|e| (e.1 == a).then_some(e.0))
        .ok_or_else(|| Error::UnknownAlgorithm(a.to_string()))
}

/// Given a packet tag, returns whether `v` is a known version.
fn known_packet_version(t: Tag, v: u8) -> bool {
    PACKET_MAP.iter().find(|e| e.1 == t)
        .map(|(_, _, versions)| versions.iter().any(|(_, known)| *known == v))
        .unwrap_or(false)
}

/// Returns whether the given packet type is versioned.
fn versioned_packet(t: Tag) -> bool {
    matches!(t,
             | Tag::PKESK
             | Tag::Signature
             | Tag::SKESK
             | Tag::OnePassSig
             | Tag::SecretKey
             | Tag::PublicKey
             | Tag::SecretSubkey
             | Tag::PublicSubkey
             | Tag::SEIP
             | Tag::AED)
}

impl Default for ConfiguredStandardPolicy<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> ConfiguredStandardPolicy<'a> {
    /// The default environment variable.
    pub const ENV_VAR: &'static str
        = "SEQUOIA_CRYPTO_POLICY";

    /// The default configuration file.
    pub const CONFIG_FILE: &'static str
        = "/etc/crypto-policies/back-ends/sequoia.config";

    /// Returns a new `ConfiguredStandardPolicy` with a default
    /// `StandardPolicy`.
    ///
    /// Normally you'll want to follow this up with a call to
    /// [`ConfiguredStandardPolicy::parse_bytes`] or
    /// [`ConfiguredStandardPolicy::parse_default_config`].
    pub fn new() -> Self {
        Self::from_policy(StandardPolicy::new())
    }

    /// Returns a new `ConfiguredStandardPolicy`.
    ///
    /// The `StandardPolicy` is created using [`StandardPolicy::at`].
    ///
    /// [`StandardPolicy::at`]: https://docs.rs/sequoia-openpgp/1.10.0/sequoia_openpgp/policy/struct.StandardPolicy.html#method.at
    ///
    /// Normally you'll want to follow this up with a call to
    /// [`ConfiguredStandardPolicy::parse_bytes`] or
    /// [`ConfiguredStandardPolicy::parse_default_config`].
    pub fn at<T>(t: T) -> Self
    where T: Into<SystemTime>
    {
        Self::from_policy(StandardPolicy::at(t))
    }

    /// Returns a new `ConfiguredStandardPolicy` using the provided
    /// `StandardPolicy`.
    ///
    /// Normally you'll want to follow this up with a call to
    /// [`ConfiguredStandardPolicy::parse_bytes`] or
    /// [`ConfiguredStandardPolicy::parse_default_config`].
    pub fn from_policy(policy: StandardPolicy<'a>) -> Self {
        ConfiguredStandardPolicy {
            policy
        }
    }

    /// Parses the configuration file specified by the environment
    /// variable.
    ///
    /// To use the default environment variable, specify
    /// [`ConfiguredStandardPolicy::ENV_VAR`].
    ///
    /// This function returns: `Ok(true)` if the policy was
    /// configured; `Ok(false)` if the policy was not configured; or,
    /// an error if there was a problem opening, reading, or parsing
    /// the configuration file.
    ///
    /// Specifically:
    ///
    ///   - If the specified environment variable is not set, this
    ///     function returns `Ok(false)` to indicate that the policy
    ///     was not configured.
    ///
    ///   - If the specified environment variable is set to the empty
    ///     string, no configuration file is read, but the policy is
    ///     considered to be configured (that is, the empty string
    ///     means to use the policy as is), and the function returns
    ///     `Ok(true)`.
    ///
    ///   - If the environment variable is set to a relative path,
    ///     this function returns an error.
    ///
    ///   - If the environment variable is set to an absolute path,
    ///     the specified file is parsed.  If an error occurs while
    ///     opening (including that the file does not exist), reading,
    ///     or parsing the configuration file, the error is returned.
    ///     If the configuration file is successfully parsed, the
    ///     function returns `Ok(true)` to indicate that the policy is
    ///     configured.
    pub fn parse_env_config(&mut self, env_var: &str) -> Result<bool> {
        let config_file = match env::var(env_var) {
            // Environment variable wasn't set.
            Err(_err) => return Ok(false),
            Ok(filename) => filename,
        };

        if config_file.is_empty() {
            // We're configured: the empty string means to just use
            // the policy as is.
            return Ok(true);
        }

        let config_file = PathBuf::from(config_file);
        if config_file.is_relative() {
            // A relative path is an error.
            let err = anyhow::Error::from(
                Error::RelativePathError(config_file));
            return Err(err)
                .context(format!("Invalid value for {}", env_var));
        }

        // We've got a configuration file.  Parse it.
        let config = match std::fs::read(&config_file) {
            Err(err) => {
                let err = anyhow::Error::from(err);
                return Err(err).with_context(|| {
                    format!("Reading {:?}", config_file)
                });
            }
            Ok(config) => config,
        };

        self.parse_bytes(config)
            .with_context(|| {
                format!("Parsing {:?}", config_file)
            })?;

        // We're configured.
        Ok(true)
    }

    /// Configures the policy using the specified configuration file.
    ///
    /// If `config_file` does not exist, returns `Ok(false)` to
    /// indicate that the policy was not configured.
    ///
    /// If an error occurs while opening, reading, or parsing the
    /// configuration file, the error is returned.
    ///
    /// Otherwise, `Ok(true)` is returned to indicate that the
    /// policy was configured.
    pub fn parse_config_file<P>(&mut self, config_file: P) -> Result<bool>
        where P: AsRef<Path>
    {
        let config_file = config_file.as_ref();

        let config = match std::fs::read(config_file) {
            Err(err) => {
                if err.kind() == io::ErrorKind::NotFound {
                    // A missing configuration file is not an error.
                    return Ok(false);
                } else {
                    let err = anyhow::Error::from(err);
                    return Err(err).with_context(|| {
                        format!("Reading {:?}", config_file)
                    });
                }
            }
            Ok(config) => config,
        };

        self.parse_bytes(config)
            .with_context(|| {
                format!("Parsing {:?}", config_file)
            })?;

        // We're configured.
        Ok(true)
    }

    /// Parses the specified configuration.
    ///
    /// This function first tries to configure the policy using the
    /// configuration file specified in the environment variable
    /// `env_var` using
    /// [`ConfiguredStandardPolicy::parse_env_config`].  If that
    /// returns `Ok(false)`, then it tries to parse `config_file`
    /// using [`ConfiguredStandardPolicy::parse_config_file`].
    pub fn parse_config<P>(&mut self, env_var: &str, config_file: P)
        -> Result<bool>
        where P: AsRef<Path>
    {
        let config_file = config_file.as_ref();

        match self.parse_env_config(env_var) {
            Ok(false) => {
                // No error and we didn't configure the policy.  Fallback
                // to the configuration file.
                self.parse_config_file(config_file)
            }
            otherwise => otherwise,
        }
    }

    /// Parses the default configuration.
    ///
    /// This first tries to parse the configuration file specified in
    /// the environment variable `SEQUOIA_CRYPTO_POLICY`.  See
    /// [`ConfiguredStandardPolicy::parse_env_config`] for the
    /// semantics.
    ///
    /// If `ConfiguredStandardPolicy::parse_env_config` doesn't
    /// configure the policy (i.e., it returns `Ok(false)`), this
    /// function tries to parse
    /// [`ConfiguredStandardPolicy::CONFIG_FILE`] using
    /// [`ConfiguredStandardPolicy::parse_config_file`].
    pub fn parse_default_config(&mut self) -> Result<bool> {
        self.parse_config(Self::ENV_VAR, Self::CONFIG_FILE)
    }

    /// Configures the policy according to the configuration data.
    pub fn parse_bytes<B>(&mut self, config: B) -> Result<()>
    where B: AsRef<[u8]>
    {
        let config = config.as_ref();
        let config = std::str::from_utf8(config)?.parse::<toml::Value>()?;

        let config = if let Value::Table(config) = config {
            config
        } else {
            return Err(Error::ParseError(
                "Expected toml sections".into()).into());
        };

        check_sections(
            None,
            &config,
            &[
                "hash_algorithms",
                "asymmetric_algorithms",
                "symmetric_algorithms",
                "aead_algorithms",
                "packets",
            ])?;

        macro_rules! doit {
            (// The name of the section (&str).
             $section_name:literal,
             // HASH_ALGO_MAP, etc.
             $algo_map:ident,
             // A callback that consumes the values:
             //
             //     fn set(default: Option<Timestamp>,
             //             properties: Vec<(AlgorithmId, Timestamp)>)
             $set:expr,
             // An iterator over all of the variants.  If the
             // default_disposition key is set, $set is called once
             // for each variant.
             $variants:expr) =>
            {
                if let Some(section) = config.get($section_name) {
                    let section = if let Value::Table(section) = section {
                        section
                    } else {
                        return Err(Error::ParseError(
                            format!("{} is not a map", $section_name)).into());
                    };

                    let mut keys = $algo_map.into_iter()
                        .map(|(k, _, _)| k)
                        .collect::<Vec<&str>>();
                    keys.push("default_disposition");
                    check_sections(
                        Some($section_name),
                        &section,
                        &keys[..])?;

                    // Handle default_disposition first.  It is the
                    // default; other settings override it.
                    if let Some(disposition) = section.iter().find_map(|(k, d)| {
                        if k == "default_disposition" {
                            Some(d)
                        } else {
                            None
                        }
                    }) {
                        match disposition.as_str() {
                            // Reject everything by default.
                            Some("never") => {
                                // We assume that all types are a u8.
                                // This is currently the case.
                                for algo in $variants {
                                    $set(algo.into(),
                                         (Some(NEVER), vec![]));
                                }
                            }
                            _ => {
                                return Err(Error::ParseError(format!(
                                    "{}.default_disposition: \
                                     invalid value ({:?}), expected never",
                                    $section_name, disposition)).into());
                            }
                        }
                    }

                    // Iterate over the keys/value pairs.
                    for (k, v) in section {
                        // We already handled "default_disposition" above.
                        if k == "default_disposition" {
                            continue;
                        }

                        // Is the key known?
                        let metadata = $algo_map
                            .into_iter()
                            .find_map(|(key, algo, props)| {
                                if k == key {
                                    Some((algo, props))
                                } else {
                                    None
                                }
                            });
                        let (algo, props) = if let Some((algo, props)) = metadata {
                            (algo, props)
                        } else {
                            // It's unknown, but in "ignore_invalid"
                            // (otherwise check_sections would have
                            // returned an error) so silently skip it.
                            continue;
                        };

                        // Parse the value.
                        let t: (Option<Timestamp>, Vec<(_, Timestamp)>) = match v {
                            Value::Datetime(_) => {
                                let t = Some(parse_time(v)?);
                                (t, vec![])
                            }
                            Value::String(_) => {
                                let t = Some(parse_time(v)?);
                                (t, vec![])
                            }
                            Value::Table(m) => {
                                // We got a table.  If this key has
                                // properties, then process them.
                                // Otherwise, only look for the
                                // default property.
                                let mut names = props
                                    .into_iter()
                                    .map(|(name, _id)| name)
                                    .cloned()
                                    .collect::<Vec<&str>>();
                                let ids = props
                                    .into_iter()
                                    .map(|(_name, id)| id)
                                    .cloned()
                                    .collect::<Vec<_>>();

                                names.push(&"default_disposition");

                                check_sections(
                                    Some(&format!("{}.{}", $section_name, k)),
                                    &m,
                                    &names[..])?;

                                let default_disposition
                                    = m.get("default_disposition")
                                    .map(parse_time).transpose()?;

                                let props: Vec<(_, Timestamp)> = names
                                    .into_iter()
                                    .zip(ids.into_iter())
                                    .filter_map(|(name, id)| {
                                        match m.get(name).map(parse_time)
                                        {
                                            Some(Ok(t)) => Some(Ok((id, t))),
                                            // Parse error.
                                            Some(Err(err)) => Some(Err(err)),
                                            // property not present.
                                            None => None,
                                        }
                                    })
                                    .collect::<Result<Vec<(_, Timestamp)>>>()?;

                                (default_disposition, props)
                            }
                            v => {
                                return Err(Error::ParseError(format!(
                                    "{}.{}: invalid value ({:?}), expected \
                                     a valid timestamp, always, or never",
                                    $section_name, k, v)).into());
                            }
                        };

                        $set(algo, t);
                    }
                }
            }
        }

        doit!("hash_algorithms",
              HASH_ALGO_MAP,
              |algo: HashAlgorithm,
               props: (Option<Timestamp>,
                       Vec<(HashAlgoSecurity, Timestamp)>)|
              {
                  let (default_disposition, props) = props;
                  if let Some(default_disposition) = default_disposition {
                      self.policy.reject_hash_property_at(
                          algo, HashAlgoSecurity::SecondPreImageResistance,
                          default_disposition);
                      self.policy.reject_hash_property_at(
                          algo, HashAlgoSecurity::CollisionResistance,
                          default_disposition);
                  }
                  for (id, value) in props {
                      self.policy.reject_hash_property_at(
                          algo, id, value);
                  }
              },
              HashAlgorithm::variants());

        doit!("asymmetric_algorithms",
              ASYMM_ALGO_MAP,
              |algo: AsymmetricAlgorithm,
               props: (Option<Timestamp>, Vec<((), Timestamp)>)|
              {
                  // No algorithm has any properties beyond the
                  // default property.
                  assert!(props.1.is_empty());
                  if let Some(t) = props.0 {
                      self.policy.reject_asymmetric_algo_at(
                          algo, t);
                  }
              },
              AsymmetricAlgorithm::variants());

        doit!("symmetric_algorithms",
              SYMM_ALGO_MAP,
              |algo: SymmetricAlgorithm,
               props: (Option<Timestamp>, Vec<((), Timestamp)>)|
              {
                  // No algorithm has any properties beyond the
                  // default property.
                  assert!(props.1.is_empty());
                  if let Some(t) = props.0 {
                      self.policy.reject_symmetric_algo_at(
                          algo, t);
                  }
              },
              SymmetricAlgorithm::variants());

        doit!("aead_algorithms",
              AEAD_ALGO_MAP,
              |algo: AEADAlgorithm,
               props: (Option<Timestamp>, Vec<((), Timestamp)>)|
              {
                  // No algorithm has any properties beyond the
                  // default property.
                  assert!(props.1.is_empty());
                  if let Some(t) = props.0 {
                      self.policy.reject_aead_algo_at(
                          algo, t);
                  }
              },
              AEADAlgorithm::variants());

        doit!("packets",
              PACKET_MAP,
              |algo: Tag,
               props: (Option<Timestamp>, Vec<(u8, Timestamp)>)|
              {
                  if let Some(default_disposition) = props.0 {
                      self.policy.reject_packet_tag_at(
                          algo, default_disposition);
                  }
                  for (version, t) in props.1 {
                      self.policy.reject_packet_tag_version_at(
                          algo, version, t);
                  }
              },
              Tag::variants());

        Ok(())
    }

    /// Returns the configured policy.
    pub fn build(self) -> StandardPolicy<'a> {
        self.policy
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Duration;

    use openpgp::Cert;
    use openpgp::parse::Parse;

    use quickcheck::{Arbitrary, Gen};

    fn arbitrary_cutoff(g: &mut Gen) -> Option<SystemTime> {
        match g.choose(&[0, 1, 2]).unwrap() {
            0 => None,
            1 => Some(UNIX_EPOCH),
            2 => Some(SystemTime::arbitrary(g)),
            _ => unreachable!(),
        }
    }

    impl Arbitrary for ConfiguredStandardPolicy<'static> {
        fn arbitrary(g: &mut Gen) -> Self {
            let mut p = ConfiguredStandardPolicy::default();

            for _ in 0..u8::arbitrary(g) {
                let cutoff = arbitrary_cutoff(g);

                match g.choose(&[0, 1, 2, 3, 4]).unwrap() {
                    // Hash algorithms.
                    0 => {
                        let variants =
                            HashAlgorithm::variants().collect::<Vec<_>>();
                        let a = g.choose(&variants).unwrap();
                        if let Some(sec) = g.choose(&[
                            Some(HashAlgoSecurity::SecondPreImageResistance),
                            Some(HashAlgoSecurity::CollisionResistance),
                            None,
                        ]).unwrap() {
                            p.policy.reject_hash_property_at(*a, *sec, cutoff);
                        } else {
                            p.policy.reject_hash_at(*a, cutoff);
                        }
                    },

                    // Symmetric algorithms.
                    1 => {
                        let variants =
                            SymmetricAlgorithm::variants().collect::<Vec<_>>();
                        let a = g.choose(&variants).unwrap();
                        p.policy.reject_symmetric_algo_at(*a, cutoff);
                    },

                    // Asymmetric algorithms.
                    2 => {
                        let variants =
                            AsymmetricAlgorithm::variants().collect::<Vec<_>>();
                        let a = g.choose(&variants).unwrap();
                        p.policy.reject_asymmetric_algo_at(*a, cutoff);
                    },

                    // AEAD algorithms.
                    3 => {
                        let variants =
                            AEADAlgorithm::variants().collect::<Vec<_>>();
                        let a = g.choose(&variants).unwrap();
                        p.policy.reject_aead_algo_at(*a, cutoff);
                    },

                    // Packets.
                    4 => {
                        let variants = Tag::variants().collect::<Vec<_>>();
                        let t = g.choose(&variants).unwrap();

                        if versioned_packet(*t) && bool::arbitrary(g) {
                            let versions =
                                PACKET_MAP.iter().find(|e| e.1 == *t).unwrap()
                                .2.iter().map(|(_, v)| *v)
                                .collect::<Vec<_>>();
                            let v = g.choose(&versions).unwrap();

                            p.policy.reject_packet_tag_version_at(
                                *t, *v, cutoff);
                        } else {
                            p.policy.reject_packet_tag_at(*t, cutoff);
                        }
                    },

                    _ => unreachable!(),
                }
            }

            p
        }
    }

    // Check that invalid sections cause an error, unless they are
    // explicitly ignored.
    #[test]
    fn invalid_section() -> Result<()> {
        let mut p = ConfiguredStandardPolicy::new();

        assert!(p.parse_bytes(b"x=1").is_err());

        // A known section.
        p.parse_bytes(b"[hash_algorithms]
sha1 = \"always\"
").expect("valid");

        // A known section and an unknown section.
        assert!(p.parse_bytes(b"[hash_algorithms]
sha1 = \"always\"

[x]
blah = 1
").is_err());

        // A known section, and an unknown section that we should
        // ignore.
        p.parse_bytes(b"ignore_invalid = \"x\"

[hash_algorithms]
sha1 = \"always\"

[x]
blah = 1
").expect("valid");

        p.parse_bytes(b"ignore_invalid = [ \"x\", \"y\" ]

[hash_algorithms]
sha1 = \"always\"

[x]
blah = 1

[y]
blah = 1
").expect("valid");

        // Section names are case sensitive.
        assert!(p.parse_bytes(b"[HASH_ALGORITHMS]
sha1 = \"never\"
").is_err());
        assert!(p.parse_bytes(b"[Hash_Algorithms]
sha1 = \"never\"
").is_err());

        // Underscores can't be replaced by spaces.
        assert!(p.parse_bytes(b"[HASH_ALGORITHMS]
sha1 = \"never\"
").is_err());

        Ok(())
    }

    // Make sure invalid keys cause an error, unless they are ignored.
    #[test]
    fn invalid_keys() -> Result<()> {
        let mut p = ConfiguredStandardPolicy::new();

        // A known section with known keys.
        p.parse_bytes(b"[hash_algorithms]
sha1 = \"always\"
sha224 = \"never\"
").expect("valid");

        // A known section with unknown keys.
        assert!(p.parse_bytes(b"[hash_algorithms]
sha1 = \"always\"
sha99 = \"never\"
").is_err());

        // A known section with unknown keys, the ignore_invalid
        // directive is in the wrong place.
        assert!(p.parse_bytes(b"
ignore_invalid = \"SHA99\"

[hash_algorithms]
sha1 = \"always\"
SHA99 = \"never\"
").is_err());

        // A known section with unknown, but ignored keys.
        p.parse_bytes(b"[hash_algorithms]
ignore_invalid = \"SHA99\"
sha1 = \"always\"
SHA99 = \"never\"
").expect("valid");

        // A known section with unknown keys, which are incorrectly
        // ignore (wrong case).
        assert!(p.parse_bytes(b"
[hash_algorithms]
ignore_invalid = \"SHA99\"
sha1 = \"always\"
sha99 = \"never\"
").is_err());

        Ok(())
    }

    /// Set one property at a time via a config file.  Check that is
    /// has been set.  Where appropriate, check that related
    /// properties have not been changed relative to the standard
    /// policy.
    #[test]
    fn get_set_one() -> Result<()> {
        let sp = StandardPolicy::new();

        let times: [(&str, Timestamp); 5] = [
            ("never", NEVER),
            ("always", ALWAYS),
            // $ date -u +%s --date='20200101'
            // 1577836800
            ("2020-01-01T00:00:00Z",
             Some(UNIX_EPOCH + Duration::new(1577836800, 0))),
            // $ date -u +%s --date='20500101'
            // 2524608000
            ("2050-01-01T00:00:00+00:00",
             Some(UNIX_EPOCH + Duration::new(2524608000, 0))),
            // $ date -u +%s --date='21050101'
            // 4260211200
            ("2105-01-01",
             Some(UNIX_EPOCH + Duration::new(4260211200, 0))),
        ];

        macro_rules! check_hash {
            ($id:expr, $algo:expr, $props:expr, $time:expr, $config:expr) => {
                let mut p = ConfiguredStandardPolicy::new();
                p.parse_bytes($config).expect("valid");
                let p = p.build();

                let all = [
                    HashAlgoSecurity::CollisionResistance,
                    HashAlgoSecurity::SecondPreImageResistance,
                ];
                for prop in all.iter().cloned() {
                    if $props.contains(&prop) {
                        assert_eq!(p.hash_cutoff(*$algo, prop),
                                   $time.1,
                                   "algo: {}, t: {}", $id, $time.0);
                    } else {
                        // Check that the other security properties
                        // didn't change.
                        assert_eq!(
                            sp.hash_cutoff(*$algo, prop),
                            p.hash_cutoff(*$algo, prop),
                            "algo: {}, t: {}", $id, $time.0);
                    }
                }
            }
        }

        for time in times.iter() {
            for (id, algo, _props) in HASH_ALGO_MAP.iter() {
                // Second preimage resistance and collision resistance.
                check_hash!(id, algo,
                            [
                                HashAlgoSecurity::SecondPreImageResistance,
                                HashAlgoSecurity::CollisionResistance,
                            ],
                            time,
                            format!(
"[hash_algorithms]
{} = \"{}\"
",
                                id, time.0));

                // Second preimage resistance.
                check_hash!(id, algo,
                            [ HashAlgoSecurity::SecondPreImageResistance ],
                            time,
                            format!(
"[hash_algorithms]
{}.second_preimage_resistance = \"{}\"
",
                                id, time.0));

                // Collision resistance.
                check_hash!(id, algo,
                            [ HashAlgoSecurity::CollisionResistance ],
                            time,
                            format!(
"[hash_algorithms]
{}.collision_resistance = \"{}\"
",
                                id, time.0));

                // Different ways of naming the key.
                check_hash!(id, algo,
                            [ HashAlgoSecurity::CollisionResistance ],
                            time,
                            format!(
"[hash_algorithms.{}]
collision_resistance = \"{}\"
",
                                id, time.0));

                check_hash!(id, algo,
                            [ HashAlgoSecurity::CollisionResistance ],
                            time,
                            format!(
"hash_algorithms.{}.collision_resistance = \"{}\"
",
                                id, time.0));
            }
        }

        macro_rules! check {
            ($id:expr, $algo:expr, $time:expr, $config:expr, $get:ident) => {
                let mut p = ConfiguredStandardPolicy::new();
                p.parse_bytes($config).expect("valid");
                let p = p.build();
                assert_eq!(p.$get($algo.clone()),
                           $time.1,
                           "algo: {}, t: {}", $id, $time.0);
            }
        }

        for time in times.iter() {
            for (id, algo, _props) in ASYMM_ALGO_MAP.iter() {
                check!(id, algo, time,
                       format!(
"[asymmetric_algorithms]
{} = \"{}\"
",
                           id, time.0),
                       asymmetric_algo_cutoff);
            }
        }

        for time in times.iter() {
            for (id, algo, _props) in SYMM_ALGO_MAP.iter() {
                check!(id, algo, time,
                       format!(
"[symmetric_algorithms]
{} = \"{}\"
",
                           id, time.0),
                       symmetric_algo_cutoff);
            }
        }

        for time in times.iter() {
            for (id, algo, _props) in AEAD_ALGO_MAP.iter() {
                check!(id, algo, time,
                       format!(
"[aead_algorithms]
{} = \"{}\"
",
                           id, time.0),
                       aead_algo_cutoff);
            }
        }

        for time in times.iter() {
            for (id, algo, props) in PACKET_MAP.into_iter() {
                // Unversioned.
                let mut p = ConfiguredStandardPolicy::new();
                p.parse_bytes(format!(
                    "[packets]
{} = \"{}\"
",
                    id, time.0)).expect("valid");
                let p = p.build();

                let cutoff = p.packet_tag_version_cutoff(algo, 1);
                assert_eq!(
                    cutoff, time.1,
                    "algo: {}, t: {}", id, time.0);

                // Setting the default means it should apply to all
                // versions, including "unknown" versions.
                for version in props.into_iter().map(|(_id, v)| v)
                    .chain(std::iter::once(&99))
                {
                    assert_eq!(
                        p.packet_tag_version_cutoff(algo.clone(), *version),
                        time.1,
                        "algo: {}, version: {}, t: {}", id, version, time.0);
                }

                // Versioned.
                for (prop, version) in props {
                    let mut p = ConfiguredStandardPolicy::new();
                    p.parse_bytes(format!(
                        "[packets]
{}.{} = \"{}\"
",
                        id, prop, time.0)).expect("valid");
                    let p = p.build();
                    assert_eq!(
                        p.packet_tag_version_cutoff(
                            algo.clone(), *version),
                        time.1,
                        "algo: {}, version: {}, t: {}",
                        id, *version, time.0);
                }
            }
        }

        Ok(())
    }

    // Convenience function for using a timestamp.
    fn ts(t: &str) -> Option<SystemTime> {
        parse_time(&Value::String(t.into())).expect("valid timestamp")
    }

    /// Check a simple config file.
    #[test]
    fn simple_config() -> Result<()> {
        // Something simple.
        let mut p = ConfiguredStandardPolicy::new();
        p.parse_bytes(b"[hash_algorithms]
sha1 = \"always\"
sha224 = 2017-03-04T13:25:35Z
sha512.second_preimage_resistance = \"always\"
sha512.collision_resistance = 2050-01-01

[symmetric_algorithms]
cast5 = \"always\"
aes128 = \"2040-01-01\"
aes256 = \"2050-01-01\"
").expect("valid config");
        let p = p.build();

        assert_eq!(
            p.hash_cutoff(HashAlgorithm::SHA1,
                          HashAlgoSecurity::SecondPreImageResistance),
            ts("always"));
        assert_eq!(
            p.hash_cutoff(HashAlgorithm::SHA224,
                          HashAlgoSecurity::SecondPreImageResistance),
            ts("2017-03-04T13:25:35Z"));

        assert_eq!(
            p.hash_cutoff(HashAlgorithm::SHA512,
                          HashAlgoSecurity::CollisionResistance),
            ts("2050-01-01"));
        assert_eq!(
            p.hash_cutoff(HashAlgorithm::SHA512,
                          HashAlgoSecurity::SecondPreImageResistance),
            ts("always"));

        assert_eq!(
            p.symmetric_algo_cutoff(SymmetricAlgorithm::CAST5),
            ts("always"));
        assert_eq!(
            p.symmetric_algo_cutoff(SymmetricAlgorithm::AES128),
            ts("2040-01-01"));
        assert_eq!(
            p.symmetric_algo_cutoff(SymmetricAlgorithm::AES256),
            ts("2050-01-01"));

        Ok(())
    }

    // Configure everything, then read it out again.
    #[test]
    fn all_config() -> Result<()> {
        let epoch = NaiveDate::from_ymd_opt(2020, 1, 1).expect("valid");
        let mut d = epoch;
        let mut date = || -> String {
            let s = d.format("%Y-%m-%d");
            d = d.succ_opt().expect("valid");
            s.to_string()
        };

        let mut config = String::new();
        config.push_str("[hash_algorithms]\n");
        for (id, algo, _props) in HASH_ALGO_MAP {
            config.push_str(
                &format!("{} = {} # {}\n", id, date(), algo));
        }
        config.push_str("\n[asymmetric_algorithms]\n");
        for (id, algo, _props) in ASYMM_ALGO_MAP {
            config.push_str(
                &format!("{} = {} # {}\n", id, date(), algo));
        }
        config.push_str("\n[symmetric_algorithms]\n");
        for (id, algo, _props) in SYMM_ALGO_MAP {
            config.push_str(
                &format!("{} = {} # {}\n", id, date(), algo));
        }
        config.push_str("\n[aead_algorithms]\n");
        for (id, algo, _props) in AEAD_ALGO_MAP {
            config.push_str(
                &format!("{} = {} # {}\n", id, date(), algo));
        }
        config.push_str("\n[packets]\n");
        for (id, algo, _props) in PACKET_MAP {
            config.push_str(
                &format!("{} = {} # {}\n", id, date(), algo));
        }

        let mut p = ConfiguredStandardPolicy::new();
        p.parse_bytes(config.clone())
            .expect(&format!("valid config: {}", config));
        let p = p.build();

        // Reset the date to the epoch.
        let mut d = epoch;
        let mut date = || -> String {
            let s = d.format("%Y-%m-%d");
            d = d.succ_opt().expect("valid");
            s.to_string()
        };

        // Make sure everything we set was really set.
        for (_, algo, _) in HASH_ALGO_MAP {
            assert_eq!(
                p.hash_cutoff(algo, HashAlgoSecurity::SecondPreImageResistance),
                ts(&date()));
        }
        for (_, algo, _) in ASYMM_ALGO_MAP {
            assert_eq!(p.asymmetric_algo_cutoff(algo), ts(&date()));
        }
        for (_, algo, _) in SYMM_ALGO_MAP {
            assert_eq!(p.symmetric_algo_cutoff(algo), ts(&date()));
        }
        for (_, algo, _) in AEAD_ALGO_MAP {
            assert_eq!(p.aead_algo_cutoff(algo), ts(&date()));
        }
        for (_, algo, props) in PACKET_MAP {
            let d = ts(&date());

            let cutoff = p.packet_tag_version_cutoff(algo, 1);
            assert_eq!(cutoff, d);

            // Setting the default means it should apply to all
            // versions, including "unknown" versions.
            for version in props.into_iter().map(|(_id, v)| v)
                .chain(std::iter::once(&99))
            {
                assert_eq!(
                    p.packet_tag_version_cutoff(algo, *version),
                    d,
                    "algo: {}, version: {}, t: {:?}", algo, version, d);
            }
        }

        Ok(())
    }

    #[test]
    fn check_sig() -> Result<()> {
        let alice = testdata::file("alice-secret.asc");

        let cert = Cert::from_bytes(alice).expect("valid cert");

        let now = ts("2022-10-30").unwrap();

        // Should be valid according to the standard policy.
        let sp = &StandardPolicy::at(now);
        let _cert = cert.with_policy(sp, None).expect("valid under standard policy");

        // If SHA512 has no collision resistance, the cert is still valid.
        let mut p = ConfiguredStandardPolicy::at(now);
        p.parse_bytes(b"[hash_algorithms]
sha512.collision_resistance = \"never\"")
            .expect(&format!("valid config"));
        let p = p.build();
        let _cert = cert.with_policy(&p, None)
            .expect("valid under: SHA512 has no collision resistance");

        // If SHA512 has no 2nd preimage resistance, the cert is not valid.
        let mut p = ConfiguredStandardPolicy::at(now);
        p.parse_bytes(b"[hash_algorithms]
sha512.second_preimage_resistance = \"never\"")
            .expect(&format!("valid config"));
        let p = p.build();
        let _cert = assert!(
            cert.with_policy(&p, None).is_err(),
            "invalid under: SHA512 has no 2nd preimage resistance");

        // If SHA512's 2nd preimage resistance is cutoff, it should be
        // invalid.
        let mut p = ConfiguredStandardPolicy::at(now);
        p.parse_bytes(&format!("[hash_algorithms]
sha512.second_preimage_resistance = 2022-10-24"))
            .expect(&format!("valid config"));
        let p = p.build();
        let _cert = assert!(
            cert.with_policy(&p, None).is_err(),
            "should be invalid under: SHA512 2nd preimage resistance cut off");

        // If SHA512's 2nd preimage resistance will be cutoff, it
        // should be invalid.
        let mut p = ConfiguredStandardPolicy::at(ts("2022-10-26").unwrap());
        p.parse_bytes(&format!("[hash_algorithms]
sha512.second_preimage_resistance = 2022-10-27"))
            .expect(&format!("valid config"));
        let p = p.build();
        let _cert = cert.with_policy(&p, ts("2022-10-26")).expect(
            "valid under: SHA512 2nd preimage resistance not yet cut off");

        let mut p = ConfiguredStandardPolicy::at(ts("2022-10-29").unwrap());
        p.parse_bytes(&format!("[hash_algorithms]
sha512.second_preimage_resistance = 2022-10-27"))
            .expect(&format!("valid config"));
        let p = p.build();
        let _cert = assert!(
            cert.with_policy(&p, ts("2022-10-28")).is_err(),
            "invalid under: SHA512 2nd preimage resistance cut off");

        Ok(())
    }

    #[test]
    fn default_disposition() -> Result<()> {
        // Reject everything.
        let mut p = ConfiguredStandardPolicy::new();
        p.parse_bytes(b"[hash_algorithms]
default_disposition = \"never\"

[asymmetric_algorithms]
default_disposition = \"never\"

[symmetric_algorithms]
default_disposition = \"never\"

[aead_algorithms]
default_disposition = \"never\"

[packets]
default_disposition = \"never\"
").expect("valid config");

        let p = p.build();

        for algo in 0..=u8::MAX {
            assert_eq!(
                p.hash_cutoff(algo.into(),
                              HashAlgoSecurity::CollisionResistance),
                Some(UNIX_EPOCH));
            assert_eq!(
                p.hash_cutoff(algo.into(),
                              HashAlgoSecurity::SecondPreImageResistance),
                Some(UNIX_EPOCH));
        }
        for (_, algo, _) in ASYMM_ALGO_MAP {
            assert_eq!(p.asymmetric_algo_cutoff(algo), Some(UNIX_EPOCH));
        }
        for algo in 0..=u8::MAX {
            assert_eq!(p.symmetric_algo_cutoff(algo.into()), Some(UNIX_EPOCH));
        }
        for algo in 0..=u8::MAX {
            assert_eq!(p.aead_algo_cutoff(algo.into()), Some(UNIX_EPOCH));
        }
        for algo in 0..=u8::MAX {
            let cutoff = p.packet_tag_version_cutoff(algo.into(), 1);
            assert_eq!(cutoff, Some(UNIX_EPOCH));
        }
        for (_, algo, props) in PACKET_MAP {
            // Setting the default means it should apply to all
            // versions, including "unknown" versions.
            for version in props.into_iter().map(|(_id, v)| v)
                .chain(std::iter::once(&99))
            {
                assert_eq!(
                    p.packet_tag_version_cutoff(algo, *version),
                    Some(UNIX_EPOCH),
                    "algo: {}, version: {}", algo, version);
            }
        }

        let mut p = ConfiguredStandardPolicy::new();
        p.parse_bytes(b"[hash_algorithms]
sha512.collision_resistance = 2050-01-01
default_disposition = \"never\"

[asymmetric_algorithms]
rsa1024 = \"always\"
default_disposition = \"never\"

[symmetric_algorithms]
aes128 = \"2040-01-01\"
aes256 = \"2050-01-01\"
default_disposition = \"never\"

[aead_algorithms]
ocb = \"always\"
default_disposition = \"never\"

[packets]
seip = \"always\"
default_disposition = \"never\"
").expect("valid config");
        let p = p.build();

        for algo in 0..=u8::MAX {
            let algo: HashAlgorithm = algo.into();

            if algo == HashAlgorithm::SHA512 {
                assert_eq!(
                    p.hash_cutoff(algo.into(),
                                  HashAlgoSecurity::CollisionResistance),
                    ts("2050-01-01"));
            } else {
                assert_eq!(
                    p.hash_cutoff(algo,
                                  HashAlgoSecurity::CollisionResistance),
                    NEVER);
            }

            assert_eq!(
                p.hash_cutoff(algo.into(),
                              HashAlgoSecurity::SecondPreImageResistance),
                NEVER);
        }

        for (_, algo, _) in ASYMM_ALGO_MAP {
            match algo {
                AsymmetricAlgorithm::RSA1024 =>
                    assert_eq!(p.asymmetric_algo_cutoff(algo), ALWAYS),
                algo =>
                    assert_eq!(p.asymmetric_algo_cutoff(algo), NEVER),
            }
        }

        for algo in 0..=u8::MAX {
            let algo = SymmetricAlgorithm::from(algo);
            match algo {
                SymmetricAlgorithm::AES128 =>
                    assert_eq!(p.symmetric_algo_cutoff(algo), ts("2040-01-01")),
                SymmetricAlgorithm::AES256 =>
                    assert_eq!(p.symmetric_algo_cutoff(algo), ts("2050-01-01")),
                algo => assert_eq!(p.symmetric_algo_cutoff(algo), NEVER),
            }
        }

        for algo in 0..=u8::MAX {
            let algo = AEADAlgorithm::from(algo);
            if algo == AEADAlgorithm::OCB {
                assert_eq!(p.aead_algo_cutoff(algo), ALWAYS);
            } else {
                assert_eq!(p.aead_algo_cutoff(algo), NEVER);
            }
        }

        for algo in 0..=u8::MAX {
            let algo = Tag::from(algo);
            let cutoff = p.packet_tag_version_cutoff(algo.into(), 1);
            if algo == Tag::SEIP {
                assert_eq!(cutoff, ALWAYS);
            } else {
                assert_eq!(cutoff, NEVER);
            }
        }
        for (_, algo, props) in PACKET_MAP {
            // Setting the default means it should apply to all
            // versions, including "unknown" versions.
            for version in props.into_iter().map(|(_id, v)| v)
                .chain(std::iter::once(&99))
            {
                let cutoff = p.packet_tag_version_cutoff(algo, *version);
                if algo == Tag::SEIP {
                    assert_eq!(cutoff, ALWAYS);
                } else {
                    assert_eq!(cutoff, NEVER);
                }
            }
        }

        Ok(())
    }

    // A string type can also be written as `key.default_disposition`.
    #[test]
    fn default_key() -> Result<()> {
        // Make sure `key` is the same as `key.default_disposition`:
        let mut p = ConfiguredStandardPolicy::new();
        p.parse_bytes(b"[hash_algorithms]
sha512.default_disposition = 2050-01-01

[symmetric_algorithms]
aes128.default_disposition = \"2040-01-01\"

[aead_algorithms]
ocb.default_disposition = \"always\"
default_disposition = \"never\"
").expect("valid config");
        let p = p.build();

        assert_eq!(
            p.hash_cutoff(HashAlgorithm::SHA512,
                          HashAlgoSecurity::CollisionResistance),
            ts("2050-01-01"));
        assert_eq!(
            p.hash_cutoff(HashAlgorithm::SHA512,
                          HashAlgoSecurity::SecondPreImageResistance),
            ts("2050-01-01"));

        assert_eq!(
            p.symmetric_algo_cutoff(SymmetricAlgorithm::AES128),
            ts("2040-01-01"));

        assert_eq!(
            p.aead_algo_cutoff(AEADAlgorithm::OCB),
            ts("always"));
        assert_eq!(
            p.aead_algo_cutoff(AEADAlgorithm::EAX),
            ts("never"));

        // `key` is a string type, which is used as a map with an
        // invalid key.
        let mut p = ConfiguredStandardPolicy::new();
        assert!(p.parse_bytes(b"[symmetric_algorithms]
aes128.foo = \"2040-01-01\"").is_err());

        // `key` is a string type, which is used as a map with an
        // invalid key, which is in ignore_invalid.
        let mut p = ConfiguredStandardPolicy::new();
        p.parse_bytes(b"[symmetric_algorithms]
aes256.foo = \"2040-01-01\"
aes256.ignore_invalid = \"foo\"
").expect("valid config");
        let p = p.build();

        let sp = &StandardPolicy::new();
        assert_eq!(
            p.symmetric_algo_cutoff(SymmetricAlgorithm::AES256),
            sp.symmetric_algo_cutoff(SymmetricAlgorithm::AES256));


        // `key` is a string type, which is used as a map with an
        // invalid key, which is in ignore_invalid, and there is a
        // default_disposition key.
        let mut p = ConfiguredStandardPolicy::new();
        p.parse_bytes(b"[symmetric_algorithms]
aes256.foo = \"2040-01-01\"
aes256.default_disposition = \"2050-01-01\"
aes256.ignore_invalid = \"foo\"
").expect("valid config");
        let p = p.build();

        assert_eq!(
            p.symmetric_algo_cutoff(SymmetricAlgorithm::AES256),
            ts("2050-01-01"));


        Ok(())
    }

    #[test]
    fn unversioned_packets() -> Result<()> {
        let mut p = ConfiguredStandardPolicy::new();
        p.parse_bytes(b"[packets]
signature = 2030-01-01
").expect("valid config");
        let p = p.build();

        assert_eq!(
            p.packet_tag_version_cutoff(Tag::Signature, 3),
            ts("2030-01-01"));
        assert_eq!(
            p.packet_tag_version_cutoff(Tag::Signature, 4),
            ts("2030-01-01"));

        Ok(())
    }

    #[test]
    fn versioned_packets() -> Result<()> {
        let mut p = ConfiguredStandardPolicy::new();
        p.parse_bytes(b"[packets]
signature.v3 = 2010-01-01
signature.v4 = 2030-01-01
").expect("valid config");
        let p = p.build();

        assert_eq!(
            p.packet_tag_version_cutoff(Tag::Signature, 3),
            ts("2010-01-01"));
        assert_eq!(
            p.packet_tag_version_cutoff(Tag::Signature, 4),
            ts("2030-01-01"));

        let mut p = ConfiguredStandardPolicy::new();
        assert!(p.parse_bytes(b"[packets]
signature.v9 = 2010-01-01
signature.v4 = 2030-01-01
").is_err());

        let mut p = ConfiguredStandardPolicy::new();
        p.parse_bytes(b"[packets]
signature.v3 = 2010-01-01
signature.v9 = 2010-01-01
signature.ignore_invalid = \"v9\"
signature.v4 = 2030-01-01
").expect("valid config");
        let p = p.build();

        assert_eq!(
            p.packet_tag_version_cutoff(Tag::Signature, 3),
            ts("2010-01-01"));
        assert_eq!(
            p.packet_tag_version_cutoff(Tag::Signature, 4),
            ts("2030-01-01"));

        // Use a default and override it for one version where the
        // override is less than the default.
        let mut p = ConfiguredStandardPolicy::new();
        p.parse_bytes(b"[packets]
signature.default_disposition = 2030-01-01
signature.v3 = 2010-01-01
").expect("valid config");
        let p = p.build();

        assert_eq!(
            p.packet_tag_version_cutoff(Tag::Signature, 3),
            ts("2010-01-01"));
        assert_eq!(
            p.packet_tag_version_cutoff(Tag::Signature, 4),
            ts("2030-01-01"));

        // Use a default and override it for one version where the
        // override is greater than the default.
        let mut p = ConfiguredStandardPolicy::new();
        p.parse_bytes(b"[packets]
signature.default_disposition = 2030-01-01
signature.v3 = 2040-01-01
").expect("valid config");
        let p = p.build();

        assert_eq!(
            p.packet_tag_version_cutoff(Tag::Signature, 3),
            ts("2040-01-01"));
        assert_eq!(
            p.packet_tag_version_cutoff(Tag::Signature, 4),
            ts("2030-01-01"));

        Ok(())
    }
}
