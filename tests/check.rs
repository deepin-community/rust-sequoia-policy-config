use std::env::current_dir;

use sequoia_openpgp as openpgp;
use openpgp::Result;

use assert_cmd::Command;
// use predicates::prelude::*;

#[test]
fn bad_config() -> Result<()> {
    let cwd = current_dir()?;
    println!("The current directory is {}", cwd.display());

    let mut cmd = Command::cargo_bin("sequoia-policy-config-check")?;
    let assert = cmd.arg("tests/config/bad.toml")
        .assert();
    assert.failure();

    Ok(())
}

#[test]
fn good_config() -> Result<()> {
    let cwd = current_dir()?;
    println!("The current directory is {}", cwd.display());

    let mut cmd = Command::cargo_bin("sequoia-policy-config-check")?;
    let assert = cmd.arg("tests/config/good.toml")
        .assert();
    assert.success();

    Ok(())
}

#[test]
fn bad_config_env() -> Result<()> {
    let cwd = current_dir()?;
    println!("The current directory is {}", cwd.display());

    let mut cmd = Command::cargo_bin("sequoia-policy-config-check")?;
    let cmd = cmd.env(
        "SEQUOIA_CRYPTO_POLICY",
        format!("{}/{}", cwd.display(), "tests/config/bad.toml"));
    let assert = cmd.assert();
    assert.failure();

    Ok(())
}

#[test]
fn good_config_env() -> Result<()> {
    let cwd = current_dir()?;
    println!("The current directory is {}", cwd.display());

    let mut cmd = Command::cargo_bin("sequoia-policy-config-check")?;
    let cmd = cmd.env(
        "SEQUOIA_CRYPTO_POLICY",
        format!("{}/{}", cwd.display(), "tests/config/good.toml"));
    let assert = cmd.assert();
    assert.success();

    Ok(())
}

// If no configuration is supplied, this will just read the default
// configuration.
#[test]
fn no_args() -> Result<()> {
    let mut cmd = Command::cargo_bin("sequoia-policy-config-check")?;
    // Make the default config a no-op in case the system
    // configuration is bad.
    cmd.env("SEQUOIA_CRYPTO_POLICY", "");
    let assert = cmd.assert();
    assert.success();

    Ok(())
}

// Using a relative path in "SEQUOIA_CRYPTO_POLICY" is not allowed.
#[test]
fn relative_path_env() -> Result<()> {
    let cwd = current_dir()?;
    println!("The current directory is {}", cwd.display());

    let mut cmd = Command::cargo_bin("sequoia-policy-config-check")?;
    let cmd = cmd.env(
        "SEQUOIA_CRYPTO_POLICY", "tests/config/good.toml");
    let assert = cmd.assert();
    assert.failure();

    Ok(())
}
