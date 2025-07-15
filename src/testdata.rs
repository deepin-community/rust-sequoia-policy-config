//! Test data.
//!
//! This module includes the test data from `tests/data` in a
//! structured way.

use std::fmt;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::OnceLock;

pub struct Test {
    path: &'static str,
    pub bytes: &'static [u8],
}

impl fmt::Display for Test {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "tests/data/{}", self.path)
    }
}

#[allow(unused)]
pub fn dir() -> PathBuf {
    PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data"))
}

/// Returns the content of the given file below `keystore/tests/data`.
pub fn file(name: &str) -> &'static [u8] {
    static FILES: OnceLock<BTreeMap<&'static str, &'static [u8]>> =
        OnceLock::new();

    FILES.get_or_init(|| {
        let mut m: BTreeMap<&'static str, &'static [u8]> =
            Default::default();

        macro_rules! add {
            ( $key: expr, $path: expr ) => {
                m.insert($key, include_bytes!($path))
            }
        }
        include!(concat!(env!("OUT_DIR"), "/tests.index.rs.inc"));

        // Sanity checks.
        assert!(m.contains_key("alice-secret.asc"));
        m
    }).get(name).unwrap_or_else(|| panic!("No such file {:?}", name))
}

