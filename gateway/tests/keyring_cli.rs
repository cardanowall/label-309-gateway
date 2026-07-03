//! End-to-end tests of the `gateway keyring` subcommands, driving the real
//! binary as a subprocess: real argv, real stdin, real environment, real files.
//!
//! The pass criterion throughout is not the CLI's own output but the
//! serve-path loader: after each lifecycle step the keyring file is opened with
//! [`gateway_core::wallet::keyring::unlock`] — the exact function the serving
//! binary boots with — and the entries are asserted where their runtime
//! consumers look for them. A CLI that printed the right things but wrote a
//! file the gateway cannot open would fail here.
//!
//! No test needs a database, so none are gated behind `pg-tests`. Each
//! subprocess gets its passphrase through the environment (set per child, never
//! on the test process) and a piped stdin, which also pins the non-interactive
//! code path deterministically.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use gateway_core::wallet::config::Network;
use gateway_core::wallet::keyring::{derive_enterprise_address, unlock};
use pallas_crypto::key::ed25519::SecretKey;
use zeroize::Zeroizing;

/// The passphrase environment variables a child must never inherit from the
/// test runner's own environment.
const PASSPHRASE_ENVS: [&str; 4] = [
    "GATEWAY_KEYRING_PASSPHRASE",
    "GATEWAY_KEYRING_PASSPHRASE_FILE",
    "GATEWAY_KEYRING_NEW_PASSPHRASE",
    "GATEWAY_KEYRING_NEW_PASSPHRASE_FILE",
];

/// Run `gateway keyring <args>` with the given child-only environment and
/// optional stdin bytes, returning the completed output. stdin is always piped
/// (closed immediately when no input is supplied), so the child never sees a
/// terminal and the environment-or-fail passphrase path is what runs.
fn run_keyring(args: &[&str], envs: &[(&str, &str)], stdin: Option<&str>) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_gateway"));
    cmd.arg("keyring").args(args);
    for name in PASSPHRASE_ENVS {
        cmd.env_remove(name);
    }
    for (name, value) in envs {
        cmd.env(name, value);
    }
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("spawn the gateway binary");
    if let Some(input) = stdin {
        child
            .stdin
            .as_mut()
            .expect("stdin is piped")
            .write_all(input.as_bytes())
            .expect("write the child's stdin");
    }
    // Dropping the handle closes the pipe so a stdin-reading child sees EOF.
    drop(child.stdin.take());
    child.wait_with_output().expect("collect the child output")
}

/// Assert success and return stdout.
fn expect_ok(output: Output, what: &str) -> String {
    assert!(
        output.status.success(),
        "{what} failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Assert failure and return stderr (where errors land).
fn expect_err(output: Output, what: &str) -> String {
    assert!(
        !output.status.success(),
        "{what} unexpectedly succeeded\nstdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Pull the value column of a `  name   value` line out of a command's stdout.
fn field(stdout: &str, name: &str) -> String {
    stdout
        .lines()
        .find_map(|line| {
            let trimmed = line.trim_start();
            trimmed
                .strip_prefix(name)
                .filter(|rest| rest.starts_with(' '))
                .map(|rest| rest.trim().to_string())
        })
        .unwrap_or_else(|| panic!("no `{name}` field in output:\n{stdout}"))
}

/// A deterministic CIP-5 signing key from a fixed seed, plus the preprod
/// address it must derive to (computed independently of the CLI).
fn fixed_wallet(seed: [u8; 32]) -> (String, String) {
    let secret = SecretKey::from(seed);
    let mut vk = [0u8; 32];
    vk.copy_from_slice(secret.public_key().as_ref());
    let hrp = bech32::Hrp::parse("ed25519_sk").expect("valid hrp");
    let bech = bech32::encode::<bech32::Bech32>(hrp, &seed).expect("encode skey");
    let address = derive_enterprise_address(&vk, Network::Preprod).expect("derive address");
    (bech, address)
}

/// The 4096-bit RSA JWK fixture the ans104 vector suite ships, as an on-disk
/// path the `--jwk` flag can read.
fn fixture_jwk_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../ans104/tests/vectors/test-jwk.json")
}

/// The address the fixture JWK must derive to, computed through the same
/// libraries the keyring uses but independently of the CLI under test.
fn fixture_jwk_address() -> String {
    let jwk = std::fs::read_to_string(fixture_jwk_path()).expect("read the fixture JWK");
    let signer = ans104::ArweaveJwkSigner::from_jwk_json(&jwk).expect("fixture JWK parses");
    gateway_core::wallet::keyring::arweave_address(&ans104::Ans104Signer::owner(&signer))
}

/// Open a CLI-written keyring with the serve-path loader.
fn unlock_file(
    path: &Path,
    passphrase: &str,
) -> gateway_core::Result<gateway_core::wallet::keyring::UnlockedKeyring> {
    let ciphertext = std::fs::read(path).expect("read the keyring file");
    unlock(
        &ciphertext,
        Zeroizing::new(passphrase.to_string()),
        Network::Preprod,
    )
}

/// The full fresh-install lifecycle: init, generate and import keys of every
/// class, inspect, duplicate refusal, removal, and a passphrase change — with
/// the serve-path unlock validating the file after every consequential step.
#[test]
fn the_cli_builds_a_keyring_the_serve_loader_opens() {
    let dir = tempfile::tempdir().expect("scratch dir");
    let path = dir.path().join("keyring.age");
    let path_str = path.to_str().expect("utf-8 path");
    let pass_env = [("GATEWAY_KEYRING_PASSPHRASE", "correct horse battery")];

    // init creates the file; a second init refuses to overwrite it.
    expect_ok(
        run_keyring(&["init", "--path", path_str], &pass_env, None),
        "init",
    );
    assert!(path.exists());
    let stderr = expect_err(
        run_keyring(&["init", "--path", path_str], &pass_env, None),
        "re-init over an existing keyring",
    );
    assert!(
        stderr.contains("already exists"),
        "the refusal names the conflict, got: {stderr}"
    );

    // A generated Cardano key lands on the requested network.
    let stdout = expect_ok(
        run_keyring(
            &["add-cardano", "--path", path_str, "--network", "preprod"],
            &pass_env,
            None,
        ),
        "add-cardano (generated)",
    );
    let generated_address = field(&stdout, "address");
    assert!(
        generated_address.starts_with("addr_test1"),
        "a preprod address starts addr_test1, got {generated_address}"
    );
    assert!(
        !stdout.contains("ed25519_sk"),
        "no secret material on stdout"
    );

    // An imported key (via --secret-stdin) gets exactly its derived address.
    let (secret_bech32, expected_address) = fixed_wallet([42u8; 32]);
    let stdout = expect_ok(
        run_keyring(
            &[
                "add-cardano",
                "--path",
                path_str,
                "--network",
                "preprod",
                "--label",
                "imported",
                "--secret-stdin",
            ],
            &pass_env,
            Some(&format!("{secret_bech32}\n")),
        ),
        "add-cardano (imported)",
    );
    assert_eq!(field(&stdout, "address"), expected_address);

    // An imported Arweave JWK gets exactly its derived address.
    let jwk_path = fixture_jwk_path();
    let stdout = expect_ok(
        run_keyring(
            &[
                "add-arweave",
                "--path",
                path_str,
                "--jwk",
                jwk_path.to_str().expect("utf-8 fixture path"),
            ],
            &pass_env,
            None,
        ),
        "add-arweave (imported)",
    );
    assert_eq!(field(&stdout, "address"), fixture_jwk_address());

    // A webhook-wrap key mints a whk_ id.
    let stdout = expect_ok(
        run_keyring(&["add-webhook-wrap", "--path", path_str], &pass_env, None),
        "add-webhook-wrap",
    );
    let wrap_key_id = field(&stdout, "key_id");
    assert!(wrap_key_id.starts_with("whk_"), "got {wrap_key_id}");

    // The same key cannot be added twice, even under a different label.
    let stderr = expect_err(
        run_keyring(
            &[
                "add-arweave",
                "--path",
                path_str,
                "--label",
                "storage-2",
                "--jwk",
                jwk_path.to_str().expect("utf-8 fixture path"),
            ],
            &pass_env,
            None,
        ),
        "duplicate arweave import",
    );
    assert!(
        stderr.contains("already holds this key"),
        "the refusal explains the duplicate, got: {stderr}"
    );

    // inspect lists every entry by kind/label/identity and prints no secret.
    let stdout = expect_ok(
        run_keyring(&["inspect", "--path", path_str], &pass_env, None),
        "inspect",
    );
    assert_eq!(field(&stdout, "entries"), "4");
    for needle in [
        generated_address.as_str(),
        expected_address.as_str(),
        wrap_key_id.as_str(),
        "cardano-ed25519",
        "arweave-rsa",
        "webhook-wrap",
        "imported",
    ] {
        assert!(stdout.contains(needle), "inspect lists {needle}:\n{stdout}");
    }
    assert!(!stdout.contains("ed25519_sk"), "no secret on stdout");

    // The serve-path loader opens the file and finds every key where its
    // runtime consumer looks for it.
    let unlocked = unlock_file(&path, "correct horse battery").expect("the serve unlock opens it");
    let wallet_addresses: Vec<String> = unlocked.wallets().into_iter().map(|w| w.address).collect();
    assert_eq!(
        wallet_addresses,
        vec![generated_address.clone(), expected_address.clone()]
    );
    assert_eq!(
        unlocked.arweave_funding_keys()[0].address,
        fixture_jwk_address()
    );
    assert_eq!(
        unlocked
            .active_webhook_wrap_key()
            .expect("wrap key present")
            .key_id(),
        wrap_key_id
    );

    // remove deletes exactly the addressed entry.
    let stdout = expect_ok(
        run_keyring(
            &["remove", "--path", path_str, "--address", &expected_address],
            &pass_env,
            None,
        ),
        "remove",
    );
    assert_eq!(field(&stdout, "entries"), "3");
    let unlocked = unlock_file(&path, "correct horse battery").expect("still opens");
    assert_eq!(
        unlocked
            .wallets()
            .into_iter()
            .map(|w| w.address)
            .collect::<Vec<_>>(),
        vec![generated_address]
    );

    // change-passphrase rotates the encryption: the old passphrase no longer
    // opens the file, the new one does, and every entry survives.
    expect_ok(
        run_keyring(
            &["change-passphrase", "--path", path_str],
            &[
                ("GATEWAY_KEYRING_PASSPHRASE", "correct horse battery"),
                ("GATEWAY_KEYRING_NEW_PASSPHRASE", "rotated passphrase"),
            ],
            None,
        ),
        "change-passphrase",
    );
    assert!(
        unlock_file(&path, "correct horse battery").is_err(),
        "the old passphrase must no longer open the keyring"
    );
    let unlocked = unlock_file(&path, "rotated passphrase").expect("the new passphrase opens it");
    assert_eq!(unlocked.wallets().len(), 1);
    assert!(unlocked.active_webhook_wrap_key().is_some());
}

/// With no passphrase in the environment and no terminal on stdin, every
/// command fails with a message that names the variables to set.
#[test]
fn a_missing_passphrase_without_a_terminal_is_a_clear_error() {
    let dir = tempfile::tempdir().expect("scratch dir");
    let path = dir.path().join("keyring.age");
    let stderr = expect_err(
        run_keyring(
            &["init", "--path", path.to_str().expect("utf-8 path")],
            &[],
            None,
        ),
        "init without a passphrase source",
    );
    assert!(
        stderr.contains("GATEWAY_KEYRING_PASSPHRASE"),
        "the error names the variable, got: {stderr}"
    );
    assert!(!path.exists(), "no file is created on failure");
}

/// Supplying the passphrase through both the plain variable and its _FILE twin
/// is ambiguous and refused — the same rule the serving binary applies.
#[test]
fn a_passphrase_from_both_sources_is_refused() {
    let dir = tempfile::tempdir().expect("scratch dir");
    let path = dir.path().join("keyring.age");
    let secret_file = dir.path().join("passphrase.txt");
    std::fs::write(&secret_file, "from-file\n").expect("write the secret file");

    let stderr = expect_err(
        run_keyring(
            &["init", "--path", path.to_str().expect("utf-8 path")],
            &[
                ("GATEWAY_KEYRING_PASSPHRASE", "direct"),
                (
                    "GATEWAY_KEYRING_PASSPHRASE_FILE",
                    secret_file.to_str().expect("utf-8 path"),
                ),
            ],
            None,
        ),
        "init with both passphrase sources",
    );
    assert!(
        stderr.contains("exactly one"),
        "the error explains the ambiguity, got: {stderr}"
    );
}

/// A wrong passphrase is refused on unlock with the opaque decryption error
/// (never a hint about which part was wrong).
#[test]
fn a_wrong_passphrase_is_refused() {
    let dir = tempfile::tempdir().expect("scratch dir");
    let path = dir.path().join("keyring.age");
    let path_str = path.to_str().expect("utf-8 path");

    expect_ok(
        run_keyring(
            &["init", "--path", path_str],
            &[("GATEWAY_KEYRING_PASSPHRASE", "right")],
            None,
        ),
        "init",
    );
    let stderr = expect_err(
        run_keyring(
            &["inspect", "--path", path_str],
            &[("GATEWAY_KEYRING_PASSPHRASE", "wrong")],
            None,
        ),
        "inspect with the wrong passphrase",
    );
    assert!(
        stderr.contains("decryption failed"),
        "the opaque decrypt error surfaces, got: {stderr}"
    );
}

/// `remove` demands exactly one stable-identity selector.
#[test]
fn remove_requires_exactly_one_selector() {
    let stderr = expect_err(
        run_keyring(
            &["remove", "--path", "/nonexistent.age"],
            &[("GATEWAY_KEYRING_PASSPHRASE", "irrelevant")],
            None,
        ),
        "remove without a selector",
    );
    assert!(stderr.contains("--address"), "got: {stderr}");

    let stderr = expect_err(
        run_keyring(
            &[
                "remove",
                "--path",
                "/nonexistent.age",
                "--address",
                "addr_test1x",
                "--key-id",
                "whk_x",
            ],
            &[("GATEWAY_KEYRING_PASSPHRASE", "irrelevant")],
            None,
        ),
        "remove with both selectors",
    );
    assert!(stderr.contains("exactly one"), "got: {stderr}");
}
