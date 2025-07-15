use std::io::Read;
use std::fs::File;

use sequoia_openpgp as openpgp;
use openpgp::Result;

use sequoia_policy_config::{ConfiguredStandardPolicy, DumpDefault};

fn usage() -> ! {
    let binary = std::env::args().next()
        .unwrap_or_else(|| String::from("sequoia-policy-config-check"));
    eprintln!("Usage: {} [--dump] [config.toml]", binary);
    eprintln!("");
    eprintln!("If no configuration is supplied, the default configuration \
               is checked.");
    std::process::exit(1);
}

fn main() -> Result<()> {
    let args = std::env::args().collect::<Vec<_>>();

    if args.len() > 3 {
        eprintln!("Expected at most two arguments.");
        usage();
    }

    let dump = args.get(1).map(|a| a == "--dump").unwrap_or(false);
    if ! dump && args.len() == 3 {
        usage();
    }

    let filename_offset = if dump { 2 } else { 1 };

    let mut p = ConfiguredStandardPolicy::new();

    if let Some(filename) = args.get(filename_offset) {
        let mut file = File::open(filename)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        p.parse_bytes(bytes)?;
    } else {
        p.parse_default_config()?;
    }

    if dump {
        p.dump(&mut std::io::stdout(), DumpDefault::Template)?;
    }

    Ok(())
}
