//! Creates a TOML template containing the current configuration.

use std::{
    collections::BTreeMap,
    io,
    time::{SystemTime, UNIX_EPOCH},
};

use sequoia_openpgp::{
    packet::Tag,
    policy::{
        AsymmetricAlgorithm,
        HashAlgoSecurity,
        StandardPolicy,
    },
    types::{
        AEADAlgorithm,
        HashAlgorithm,
        SymmetricAlgorithm,
    },
};

use crate::{
    AEAD_ALGO_MAP,
    ASYMM_ALGO_MAP,
    ConfiguredStandardPolicy,
    HASH_ALGO_MAP,
    PACKET_MAP,
    Result,
    SYMM_ALGO_MAP,
    algo_to_key,
    known_packet_version,
    versioned_packet,
};

/// Controls how [`ConfiguredStandardPolicy::dump`] emits default
/// values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DumpDefault {
    /// Default values are not emitted.
    ///
    /// The advantage is that changes to the `StandardPolicy`'s
    /// defaults are picked up by applications using a policy
    /// configuration emitted by
    /// [`ConfiguredStandardPolicy::dump`].
    ///
    /// The disadvantage is that the defaults are somewhat opaque,
    /// i.e. hard to discover and adjust for the user.  Or, it may be
    /// that the intent of writing out the policy configuration is to
    /// freeze the policy, i.e. prevent updates to the
    /// `StandardPolicy`'s defaults to become effective.
    Implicit,

    /// Defaults are emitted, but commented out.
    ///
    /// Represents a middle ground between [`DumpDefault::Implicit`]
    /// and [`DumpDefault::Explicit`]: it allows the
    /// `StandardPolicy`'s defaults to evolve, while allowing the user
    /// to discover and tweak the results if they wish.
    Template,

    /// Default values are made explicit.
    ///
    /// The advantage is that default values are made explicit, so
    /// that users can discover and tweak them.  Further, the current
    /// policy is frozen, i.e. it prevents updates to the
    /// `StandardPolicy`'s defaults from becoming effective.
    ///
    /// The downside is that the policy is frozen, so users are at
    /// risk of using a stale policy configuration.
    Explicit,
}

impl DumpDefault {
    /// Emits the key according to the variant.
    fn emit(&self,
            sink: &mut dyn io::Write,
            cutoff: Option<SystemTime>,
            cutoff_ref: Option<SystemTime>,
            key: &str) -> Result<()>
    {
        self.emit_cond(sink, cutoff, cutoff == cutoff_ref, key)
    }

    /// Emits the key according to the variant depending on `omit`.
    fn emit_cond(&self,
                 sink: &mut dyn io::Write,
                 cutoff: Option<SystemTime>,
                 omit: bool,
                 key: &str) -> Result<()>
    {
        if omit {
            match self {
                DumpDefault::Implicit => return Ok(()),
                DumpDefault::Template => write!(sink, "#")?,
                DumpDefault::Explicit => (),
            }
        }
        writeln!(sink, "{} = {}", key, format_value(cutoff))?;
        Ok(())
    }
}

impl ConfiguredStandardPolicy<'_> {
    /// Writes the configuration to `sink`.
    ///
    /// Writes the configuration to the given writer, so that when the
    /// policy configuration is parsed again, it results in a policy
    /// that behaves the same way as this one.
    ///
    /// The handling of default cutoff times can be tweaked using the
    /// [`DumpDefault`] parameter: they can be omitted, emitted but
    /// commented out, or emitted.
    ///
    /// Note that if this policy has been read from a file, this does
    /// not necessarily reproduce that file exactly: as the parser
    /// ignores any unknown values, they are not represented in the
    /// parsed policy.  Further, any default disposition settings are
    /// lost, as they only affect the parsing, and are not represented
    /// in the resulting policy.
    pub fn dump(&self, sink: &mut dyn io::Write, w: DumpDefault)
                     -> Result<()>
    {
        const REF: StandardPolicy = StandardPolicy::new();

        writeln!(sink, "[hash_algorithms]")?;
        for a in HashAlgorithm::variants() {
            let spir = self.policy.hash_cutoff(
                a, HashAlgoSecurity::SecondPreImageResistance);
            let spir_ref = REF.hash_cutoff(
                a, HashAlgoSecurity::SecondPreImageResistance);
            let cr = self.policy.hash_cutoff(
                a, HashAlgoSecurity::CollisionResistance);
            let cr_ref = REF.hash_cutoff(
                a, HashAlgoSecurity::CollisionResistance);

            if spir == cr {
                w.emit(sink, spir, spir_ref, algo_to_key(&HASH_ALGO_MAP, a)?)?;
            } else {
                w.emit(sink, spir, spir_ref,
                       &format!("{}.second_preimage_resistance",
                                algo_to_key(&HASH_ALGO_MAP, a)?))?;
                w.emit(sink, cr, cr_ref,
                       &format!("{}.collision_resistance",
                                algo_to_key(&HASH_ALGO_MAP, a)?))?;
            }
        }

        writeln!(sink)?;
        writeln!(sink, "[symmetric_algorithms]")?;
        for a in SymmetricAlgorithm::variants() {
            let cutoff = self.policy.symmetric_algo_cutoff(a);
            let cutoff_ref = REF.symmetric_algo_cutoff(a);
            w.emit(sink, cutoff, cutoff_ref, algo_to_key(&SYMM_ALGO_MAP, a)?)?;
        }

        writeln!(sink)?;
        writeln!(sink, "[asymmetric_algorithms]")?;
        for a in AsymmetricAlgorithm::variants() {
            let cutoff = self.policy.asymmetric_algo_cutoff(a);
            let cutoff_ref = REF.asymmetric_algo_cutoff(a);
            w.emit(sink, cutoff, cutoff_ref, algo_to_key(&ASYMM_ALGO_MAP, a)?)?;
        }

        writeln!(sink)?;
        writeln!(sink, "[aead_algorithms]")?;
        for a in AEADAlgorithm::variants() {
            let cutoff = self.policy.aead_algo_cutoff(a);
            let cutoff_ref = REF.aead_algo_cutoff(a);
            w.emit(sink, cutoff, cutoff_ref, algo_to_key(&AEAD_ALGO_MAP, a)?)?;
        }

        writeln!(sink)?;
        writeln!(sink, "[packets]")?;
        for t in Tag::variants() {
            if versioned_packet(t) {
                // We need to be clever here.  First, compute a
                // histogram of packet version cutoffs.
                let mut histo: BTreeMap<Option<SystemTime>, Vec<u8>>
                    = Default::default();

                // Constant cutoff time in the reference?
                let mut ref_constant = true;
                let ref_0 = REF.packet_tag_version_cutoff(t, 0);

                for v in 0..=255 {
                    let cutoff = self.policy.packet_tag_version_cutoff(t, v);
                    histo.entry(cutoff).or_default().push(v);

                    ref_constant &=
                        REF.packet_tag_version_cutoff(t, v) == ref_0;
                }

                if histo.len() == 1 {
                    // All versions have the same cutoff.  Collapse
                    // into unversioned cutoff.
                    let cutoff = *histo.keys().next().unwrap();
                    let cutoff_ref = REF.packet_tag_version_cutoff(t, 0);
                    w.emit_cond(sink, cutoff,
                                cutoff == cutoff_ref && ref_constant,
                                algo_to_key(&PACKET_MAP, t)?)?;
                    continue;
                }

                // Collapse the largest group into the default
                // disposition.
                let mut histo = histo.into_iter().collect::<Vec<_>>();

                histo.sort_by_key(|(_, versions)| versions.len());
                let (default_disposition, default_group) =
                    histo.pop().unwrap();
                let default_ref =
                    REF.packet_tag_version_cutoff(t, default_group[0]);
                w.emit_cond(sink, default_disposition,
                            default_disposition == default_ref && ref_constant,
                            &format!("{}.default_disposition",
                                     algo_to_key(&PACKET_MAP, t)?))?;

                let mut unknown_versions = Vec::new();
                for (cutoff, versions) in histo {
                    for v in versions {
                        let cutoff_ref =
                            REF.packet_tag_version_cutoff(t, v);

                        w.emit_cond(
                            sink, cutoff,
                            cutoff == cutoff_ref
                                && cutoff == default_disposition,
                            &format!("{}.v{}", algo_to_key(&PACKET_MAP, t)?,
                                     v))?;

                        if ! known_packet_version(t, v) {
                            unknown_versions.push(format!("v{}", v));
                        }
                    }
                }

                if ! unknown_versions.is_empty() {
                    writeln!(sink, "{}.ignore_invalid = {:?}",
                             algo_to_key(&PACKET_MAP, t)?,
                             &unknown_versions)?;
                }
            } else {
                let cutoff = self.policy.packet_tag_version_cutoff(t, 0);
                let cutoff_ref = REF.packet_tag_version_cutoff(t, 0);
                w.emit(sink, cutoff, cutoff_ref, algo_to_key(&PACKET_MAP, t)?)?;
            }
        }

        Ok(())
    }
}

/// Formats the given cutoff value.
fn format_value(v: Option<SystemTime>) -> String {
    match v {
        None => "\"always\"".into(),
        Some(cutoff) => if cutoff == UNIX_EPOCH {
            "\"never\"".into()
        } else {
            use chrono::{DateTime, NaiveTime, Utc};
            let d: DateTime<Utc> = cutoff.into();

            if d.time().signed_duration_since(
                NaiveTime::from_hms_opt(0, 0, 0).unwrap()).is_zero()
            {
                d.format("%Y-%m-%d").to_string()
            } else {
                d.format("%Y-%m-%dT%H:%M:%SZ").to_string()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_default() -> Result<()> {
        test_roundtrip(Default::default())
    }

    quickcheck::quickcheck! {
        fn roundtrip(p: ConfiguredStandardPolicy<'static>) -> bool {
            test_roundtrip(p).unwrap();
            true
        }
    }

    fn test_roundtrip(p: ConfiguredStandardPolicy) -> Result<()> {
        for v in [DumpDefault::Explicit,
                  DumpDefault::Template,
                  DumpDefault::Implicit]
        {
            let mut sink = Vec::new();
            p.dump(&mut sink, v)?;

            eprintln!("{:?}:", v);
            eprintln!("{}", std::str::from_utf8(&sink)?);

            let mut q = ConfiguredStandardPolicy::new();
            q.parse_bytes(&sink)?;

            assert_effectively_eq(&p.policy, &q.policy);
        }

        Ok(())
    }

    fn assert_effectively_eq(a: &StandardPolicy, b:&StandardPolicy) {
        // XXX: The parser ignores unknown algorithms, even though the
        // standard policy could represent them.  Therefore, we only
        // compare known algorithms.
        for alg in HashAlgorithm::variants() {
            assert_eq!(
                a.hash_cutoff(alg, HashAlgoSecurity::SecondPreImageResistance),
                b.hash_cutoff(alg, HashAlgoSecurity::SecondPreImageResistance),
                "differ on second preimage resistance cutoff for {}", alg);
            assert_eq!(
                a.hash_cutoff(alg, HashAlgoSecurity::CollisionResistance),
                b.hash_cutoff(alg, HashAlgoSecurity::CollisionResistance),
                "differ on collision resistance cutoff for {}", alg);
        }

        for alg in SymmetricAlgorithm::variants() {
            assert_eq!(
                a.symmetric_algo_cutoff(alg),
                b.symmetric_algo_cutoff(alg),
                "differ on symmetric algo cutoff for {}", alg);
        }

        for alg in AEADAlgorithm::variants() {
            assert_eq!(
                a.aead_algo_cutoff(alg),
                b.aead_algo_cutoff(alg),
                "differ on aead algo cutoff for {}", alg);
        }

        for alg in AsymmetricAlgorithm::variants() {
            assert_eq!(
                a.asymmetric_algo_cutoff(alg),
                b.asymmetric_algo_cutoff(alg),
                "differ on asymmetric algo cutoff for {}", alg);
        }

        for t in Tag::variants() {
            for v in 0..=255 {
                // XXX: The parser flat out ignores unknown packet
                // versions, even though the standard policy can
                // represent unknown values.  Therefore, we only
                // compare known versions.
                if ! known_packet_version(t, v) {
                    continue;
                }

                assert_eq!(
                    a.packet_tag_version_cutoff(t, v),
                    b.packet_tag_version_cutoff(t, v),
                    "differ on {} version {} cutoff", t, v);
            }
        }
    }
}
