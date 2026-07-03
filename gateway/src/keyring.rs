//! The `gateway keyring …` subcommands: create and edit the operator keyring.
//!
//! The keyring is the age-encrypted envelope of operator keys the serving
//! binary unlocks at boot — the Cardano ed25519 wallet keys that sign anchoring
//! transactions, the Arweave RSA keys that sign storage data items, and the
//! webhook secret-wrap data keys. These subcommands own its whole lifecycle, so
//! an operator never hand-assembles the JSON or reaches for external key and
//! encryption tooling. Every command drives the engine's
//! [`gateway_core::wallet::keyring_edit::KeyringEditor`], which derives each
//! entry's identity with the same functions the serve-path unlock re-checks and
//! round-trips every mutation through a real unlock before this module writes
//! the file: a keyring this CLI produces is always one the gateway can open.
//!
//! Secrets never reach stdout or stderr — the commands print addresses, labels,
//! and key ids only, and install no tracing subscriber, so nothing here can
//! route key material through a logger. The passphrase comes from
//! `GATEWAY_KEYRING_PASSPHRASE` (or its `_FILE` twin), exactly as the serving
//! binary sources it; when neither is set and stdin is a terminal, the command
//! prompts interactively with echo off. Writes are atomic (a temp file in the
//! keyring's directory, then a rename) with owner-only permissions on Unix, so
//! a crash mid-write can never leave a truncated keyring behind.

use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use gateway_core::wallet::config::Network;
use gateway_core::wallet::keyring_edit::KeyringEditor;
use zeroize::Zeroizing;

use crate::config;

/// Run the `gateway keyring …` command from its argument list (everything after
/// `keyring`). Prints results to stdout and returns an error the caller
/// surfaces as a non-zero exit.
pub fn run(args: &[String]) -> Result<()> {
    let Some(action) = args.first().map(String::as_str) else {
        print_usage();
        bail!("keyring requires a subcommand");
    };
    let rest = &args[1..];
    match action {
        "init" => init(rest),
        "add-cardano" => add_cardano(rest),
        "add-arweave" => add_arweave(rest),
        "add-webhook-wrap" => add_webhook_wrap(rest),
        "inspect" => inspect(rest),
        "remove" => remove(rest),
        "change-passphrase" => change_passphrase(rest),
        other => {
            print_usage();
            bail!("unknown keyring subcommand: {other}")
        }
    }
}

/// Create a new, empty keyring file. Refuses to touch an existing file.
fn init(args: &[String]) -> Result<()> {
    let parsed = Args::parse(args, &["--path"], &[])?;
    let path = parsed.path()?;
    // Checked before the passphrase is sourced so an operator with no
    // environment set is not prompted only to be refused; the atomic write
    // below re-checks without a race (`persist_noclobber`).
    if path.exists() {
        bail!(
            "a file already exists at {}; `keyring init` refuses to overwrite a keyring",
            path.display()
        );
    }

    let passphrase = creation_passphrase()?;
    let ciphertext = KeyringEditor::new()
        .encrypt(&passphrase)
        .context("encrypting the new keyring")?;
    write_keyring(&path, &ciphertext, true)?;

    println!("keyring init complete");
    println!("  path     {}", path.display());
    println!();
    println!("  The keyring is empty. Add keys with `gateway keyring add-cardano`,");
    println!("  `gateway keyring add-arweave`, and `gateway keyring add-webhook-wrap`.");
    Ok(())
}

/// Add a Cardano ed25519 signing key: generated fresh by default, or imported
/// from stdin with `--secret-stdin`.
fn add_cardano(args: &[String]) -> Result<()> {
    let parsed = Args::parse(
        args,
        &["--path", "--network", "--label"],
        &["--secret-stdin"],
    )?;
    let path = parsed.path()?;
    let network = Network::parse(parsed.require("--network")?)
        .map_err(|e| anyhow!("--network: {e} (expected mainnet, preprod, or preview)"))?;
    let label = parsed.get("--label").unwrap_or("primary");

    let passphrase = existing_passphrase()?;
    let mut editor = load_editor(&path, &passphrase)?;
    let summary = if parsed.has("--secret-stdin") {
        let secret = read_secret_from_stdin("a CIP-5 signing key (ed25519_sk1…)")?;
        editor
            .import_cardano(label, network, secret)
            .context("importing the signing key")?
    } else {
        editor
            .generate_cardano(label, network)
            .context("generating a signing key")?
    };
    save_keyring(&path, &editor, &passphrase)?;

    println!("keyring add-cardano complete");
    println!("  label    {label}");
    println!("  network  {}", network.as_str());
    println!("  address  {}", summary.identity);
    println!();
    println!("  The signing key stays inside the keyring and is never printed. Fund the");
    println!("  address and register it on the control plane (`gateway admin wallet");
    println!("  register`) to let the gateway submit anchoring transactions with it.");
    Ok(())
}

/// Add an Arweave RSA storage key: generated fresh by default (4096-bit), or
/// imported from a JWK file with `--jwk`.
fn add_arweave(args: &[String]) -> Result<()> {
    let parsed = Args::parse(args, &["--path", "--label", "--jwk"], &[])?;
    let path = parsed.path()?;
    let label = parsed.get("--label").unwrap_or("storage");

    let passphrase = existing_passphrase()?;
    let mut editor = load_editor(&path, &passphrase)?;
    let summary = match parsed.get("--jwk") {
        Some(jwk_path) => {
            let jwk = Zeroizing::new(std::fs::read_to_string(jwk_path).with_context(|| {
                format!("reading the RSA key file {jwk_path} (expected JWK JSON)")
            })?);
            editor
                .import_arweave(label, jwk)
                .context("importing the Arweave RSA key")?
        }
        None => {
            // Prime search for a 4096-bit key is genuinely slow; say so rather
            // than look hung.
            println!("generating a fresh 4096-bit Arweave RSA key (this can take a moment)…");
            editor
                .generate_arweave(label)
                .context("generating an Arweave RSA key")?
        }
    };
    save_keyring(&path, &editor, &passphrase)?;

    println!("keyring add-arweave complete");
    println!("  label    {label}");
    println!("  address  {}", summary.identity);
    println!();
    println!("  The RSA key stays inside the keyring and is never printed. Fund this");
    println!("  Arweave address (or its bundler credit) and register it on the control");
    println!("  plane (`gateway admin storage source register`) to serve uploads.");
    Ok(())
}

/// Add a webhook secret-wrap data key (always generated; there is nothing to
/// import — the key exists only inside keyrings).
fn add_webhook_wrap(args: &[String]) -> Result<()> {
    let parsed = Args::parse(args, &["--path", "--label"], &[])?;
    let path = parsed.path()?;
    let label = parsed.get("--label").unwrap_or("webhook-wrap");

    let passphrase = existing_passphrase()?;
    let mut editor = load_editor(&path, &passphrase)?;
    let summary = editor
        .generate_webhook_wrap(label)
        .context("generating a webhook secret-wrap key")?;
    save_keyring(&path, &editor, &passphrase)?;

    println!("keyring add-webhook-wrap complete");
    println!("  label    {label}");
    println!("  key_id   {}", summary.identity);
    println!();
    println!("  Webhook signing secrets are encrypted at rest under this key. The newest");
    println!("  webhook-wrap entry is the active one, so adding another later is a rotation.");
    Ok(())
}

/// Unlock the keyring and list its entries: kind, label, and stable identity.
/// Never prints secret material.
fn inspect(args: &[String]) -> Result<()> {
    let parsed = Args::parse(args, &["--path"], &[])?;
    let path = parsed.path()?;

    let passphrase = existing_passphrase()?;
    // The editor's decrypt runs the full serve-path verification, so a clean
    // inspect doubles as proof the gateway could boot with this file.
    let editor = load_editor(&path, &passphrase)?;

    println!("keyring inspect");
    println!("  path     {}", path.display());
    println!("  entries  {}", editor.len());
    if !editor.is_empty() {
        println!();
        println!("  {:<17} {:<16} identity", "kind", "label");
        for summary in editor.summaries() {
            println!(
                "  {:<17} {:<16} {}",
                summary.kind.as_str(),
                summary.label,
                summary.identity
            );
        }
    }
    Ok(())
}

/// Remove one entry by its stable identity: `--address` for a signing key,
/// `--key-id` for a webhook-wrap key.
fn remove(args: &[String]) -> Result<()> {
    let parsed = Args::parse(args, &["--path", "--address", "--key-id"], &[])?;
    let path = parsed.path()?;
    let identity = match (parsed.get("--address"), parsed.get("--key-id")) {
        (Some(_), Some(_)) => bail!("pass exactly one of --address or --key-id"),
        (Some(address), None) => address,
        (None, Some(key_id)) => key_id,
        (None, None) => {
            bail!("pass --address <addr> (a signing key) or --key-id <id> (a webhook-wrap key)")
        }
    };

    let passphrase = existing_passphrase()?;
    let mut editor = load_editor(&path, &passphrase)?;
    let summary = editor.remove(identity).context("removing the entry")?;
    save_keyring(&path, &editor, &passphrase)?;

    println!("keyring remove complete");
    println!(
        "  removed  {} {:?} ({})",
        summary.kind.as_str(),
        summary.label,
        summary.identity
    );
    println!("  entries  {}", editor.len());
    Ok(())
}

/// Re-encrypt the keyring under a new passphrase. The current passphrase comes
/// from the normal sourcing; the new one from `GATEWAY_KEYRING_NEW_PASSPHRASE`
/// (or its `_FILE` twin), or an interactive confirmed prompt.
fn change_passphrase(args: &[String]) -> Result<()> {
    let parsed = Args::parse(args, &["--path"], &[])?;
    let path = parsed.path()?;

    let current = existing_passphrase()?;
    let editor = load_editor(&path, &current)?;
    let next = new_passphrase()?;
    let ciphertext = editor
        .encrypt(&next)
        .context("re-encrypting the keyring under the new passphrase")?;
    write_keyring(&path, &ciphertext, false)?;

    println!("keyring change-passphrase complete");
    println!("  path     {}", path.display());
    println!("  entries  {}", editor.len());
    println!();
    println!("  The keyring is re-encrypted under the new passphrase; update the");
    println!(
        "  {} secret the serving binary boots with.",
        config::KEYRING_PASSPHRASE_ENV
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Passphrase sourcing.
// ---------------------------------------------------------------------------

/// Resolve the passphrase that unlocks an existing keyring: the environment
/// pair first (the serve path's convention), then an interactive prompt.
fn existing_passphrase() -> Result<Zeroizing<String>> {
    match config::keyring_passphrase_from_env()? {
        Some(passphrase) => non_empty(passphrase, config::KEYRING_PASSPHRASE_ENV),
        None => prompt_passphrase(
            "Keyring passphrase: ",
            false,
            config::KEYRING_PASSPHRASE_ENV,
            config::KEYRING_PASSPHRASE_FILE_ENV,
        ),
    }
}

/// Resolve the passphrase a NEW keyring is created under (`init`): the normal
/// environment pair, or an interactive prompt WITH confirmation — a typo in an
/// unconfirmed creation passphrase locks the operator out of the file.
fn creation_passphrase() -> Result<Zeroizing<String>> {
    match config::keyring_passphrase_from_env()? {
        Some(passphrase) => non_empty(passphrase, config::KEYRING_PASSPHRASE_ENV),
        None => prompt_passphrase(
            "New keyring passphrase: ",
            true,
            config::KEYRING_PASSPHRASE_ENV,
            config::KEYRING_PASSPHRASE_FILE_ENV,
        ),
    }
}

/// Resolve the NEW passphrase for `change-passphrase`: its dedicated
/// environment pair, or an interactive prompt with confirmation.
fn new_passphrase() -> Result<Zeroizing<String>> {
    match config::keyring_new_passphrase_from_env()? {
        Some(passphrase) => non_empty(passphrase, config::KEYRING_NEW_PASSPHRASE_ENV),
        None => prompt_passphrase(
            "New keyring passphrase: ",
            true,
            config::KEYRING_NEW_PASSPHRASE_ENV,
            config::KEYRING_NEW_PASSPHRASE_FILE_ENV,
        ),
    }
}

/// Refuse an empty passphrase from the environment: an empty value protects
/// nothing and is far more likely a mis-set variable than an intent.
fn non_empty(passphrase: Zeroizing<String>, source: &str) -> Result<Zeroizing<String>> {
    if passphrase.is_empty() {
        bail!("{source} is set but empty; a keyring passphrase must not be empty");
    }
    Ok(passphrase)
}

/// Prompt for a passphrase with echo off, or fail with a clear pointer at the
/// environment pair when there is no terminal to prompt on.
///
/// `confirm` asks twice and requires the answers to match — used wherever the
/// passphrase is being SET (init, change-passphrase), where an unconfirmed typo
/// would lock the operator out. The prompt reads from the controlling terminal,
/// not stdin, so it composes with `--secret-stdin` (which consumes stdin).
fn prompt_passphrase(
    prompt: &str,
    confirm: bool,
    env: &str,
    env_file: &str,
) -> Result<Zeroizing<String>> {
    if !std::io::stdin().is_terminal() {
        bail!(
            "no keyring passphrase: set {env} (or {env_file}), or run interactively on a terminal"
        );
    }
    let first = Zeroizing::new(
        rpassword::prompt_password(prompt).context("reading the passphrase from the terminal")?,
    );
    if first.is_empty() {
        bail!("the keyring passphrase must not be empty");
    }
    if confirm {
        let second = Zeroizing::new(
            rpassword::prompt_password("Confirm passphrase: ")
                .context("reading the passphrase confirmation from the terminal")?,
        );
        if *first != *second {
            bail!("the passphrases do not match");
        }
    }
    Ok(first)
}

// ---------------------------------------------------------------------------
// File handling.
// ---------------------------------------------------------------------------

/// Read and decrypt the keyring at `path` for editing. The editor's decrypt
/// runs the same per-entry verification the serve-path unlock does.
fn load_editor(path: &Path, passphrase: &str) -> Result<KeyringEditor> {
    let ciphertext = std::fs::read(path).with_context(|| {
        format!(
            "reading the keyring at {} (run `gateway keyring init` to create one)",
            path.display()
        )
    })?;
    KeyringEditor::decrypt(&ciphertext, passphrase)
        .with_context(|| format!("unlocking the keyring at {}", path.display()))
}

/// Encrypt the editor's state (which round-trips it through a real unlock) and
/// write it over the existing file atomically.
fn save_keyring(path: &Path, editor: &KeyringEditor, passphrase: &str) -> Result<()> {
    let ciphertext = editor
        .encrypt(passphrase)
        .context("re-encrypting the keyring")?;
    write_keyring(path, &ciphertext, false)
}

/// Write the ciphertext atomically: a temp file in the keyring's own directory
/// (so the final rename never crosses a filesystem), fsynced, owner-only on
/// Unix, then renamed into place. `create_new` refuses to replace an existing
/// file (the `init` guarantee), race-free at the rename.
fn write_keyring(path: &Path, ciphertext: &[u8], create_new: bool) -> Result<()> {
    let dir = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let mut temp = tempfile::Builder::new()
        .prefix(".keyring.")
        .tempfile_in(dir)
        .with_context(|| format!("creating a temporary file in {}", dir.display()))?;

    // Owner-only before any bytes land. The content is ciphertext, but the file
    // IS the operator's key custody; nothing about it should be group-readable.
    // (tempfile already creates 0600 files on Unix; set it explicitly so the
    // guarantee is this function's, not a dependency default's.)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .context("restricting the keyring file permissions")?;
    }

    temp.write_all(ciphertext)
        .context("writing the keyring ciphertext")?;
    temp.as_file()
        .sync_all()
        .context("flushing the keyring to disk")?;

    let persisted = if create_new {
        temp.persist_noclobber(path)
    } else {
        temp.persist(path)
    };
    persisted.map_err(|e| anyhow!("writing the keyring at {}: {}", path.display(), e.error))?;

    // Fsync the containing directory so the rename itself is durable, not just
    // the file's bytes: a crash right after this returns must not lose the new
    // directory entry on filesystems that don't journal the rename eagerly.
    if let Ok(handle) = std::fs::File::open(dir) {
        handle
            .sync_all()
            .with_context(|| format!("flushing the directory {}", dir.display()))?;
    }
    Ok(())
}

/// Read a secret from stdin (the `--secret-stdin` import path), trimmed of
/// surrounding whitespace, into a zeroizing buffer.
fn read_secret_from_stdin(what: &str) -> Result<Zeroizing<String>> {
    let mut raw = Zeroizing::new(String::new());
    std::io::stdin()
        .read_to_string(&mut raw)
        .context("reading the secret from stdin")?;
    let secret = Zeroizing::new(raw.trim().to_string());
    if secret.is_empty() {
        bail!("stdin carried no secret; pipe {what} into the command");
    }
    Ok(secret)
}

// ---------------------------------------------------------------------------
// Argument parsing.
// ---------------------------------------------------------------------------

/// The parsed arguments of one subcommand: `--flag value` pairs and boolean
/// switches. Parsing is strict — an unknown argument is an error, never
/// silently ignored, because a typo'd flag on a key-management command must not
/// change its meaning quietly. No secret ever travels as a flag value (secrets
/// arrive via stdin, a named file, or the environment), so the derived `Debug`
/// is safe.
#[derive(Debug)]
struct Args {
    values: Vec<(&'static str, String)>,
    switches: Vec<&'static str>,
}

impl Args {
    /// Parse `args` against the value-taking flags and boolean switches this
    /// subcommand accepts.
    fn parse(
        args: &[String],
        value_flags: &[&'static str],
        switch_flags: &[&'static str],
    ) -> Result<Self> {
        let mut values: Vec<(&'static str, String)> = Vec::new();
        let mut switches: Vec<&'static str> = Vec::new();
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            if let Some(flag) = value_flags.iter().find(|f| **f == arg.as_str()) {
                let value = iter
                    .next()
                    .cloned()
                    .ok_or_else(|| anyhow!("{flag} requires a value"))?;
                if values.iter().any(|(name, _)| name == flag) {
                    bail!("{flag} is given more than once");
                }
                values.push((flag, value));
            } else if let Some(flag) = switch_flags.iter().find(|f| **f == arg.as_str()) {
                if !switches.contains(flag) {
                    switches.push(flag);
                }
            } else {
                bail!("unknown argument {arg:?}");
            }
        }
        Ok(Self { values, switches })
    }

    /// The value of a flag, if given.
    fn get(&self, flag: &str) -> Option<&str> {
        self.values
            .iter()
            .find(|(name, _)| *name == flag)
            .map(|(_, value)| value.as_str())
    }

    /// The value of a required flag.
    fn require(&self, flag: &str) -> Result<&str> {
        self.get(flag)
            .ok_or_else(|| anyhow!("{flag} <value> is required"))
    }

    /// Whether a boolean switch was given.
    fn has(&self, flag: &str) -> bool {
        self.switches.contains(&flag)
    }

    /// The required `--path` flag as a path.
    fn path(&self) -> Result<PathBuf> {
        Ok(PathBuf::from(self.require("--path")?))
    }
}

/// Print the subcommand usage to stderr.
fn print_usage() {
    eprintln!("usage: gateway keyring <subcommand> --path <file> [flags]");
    eprintln!("  init              --path <file>");
    eprintln!("  add-cardano       --path <file> --network <mainnet|preprod|preview>");
    eprintln!("                    [--label <l>] [--secret-stdin]");
    eprintln!("  add-arweave       --path <file> [--label <l>] [--jwk <jwk-file>]");
    eprintln!("  add-webhook-wrap  --path <file> [--label <l>]");
    eprintln!("  inspect           --path <file>");
    eprintln!("  remove            --path <file> (--address <addr> | --key-id <id>)");
    eprintln!("  change-passphrase --path <file>");
    eprintln!();
    eprintln!("The keyring passphrase comes from GATEWAY_KEYRING_PASSPHRASE (or its _FILE");
    eprintln!("twin), or an interactive prompt when stdin is a terminal. change-passphrase");
    eprintln!("reads the new passphrase from GATEWAY_KEYRING_NEW_PASSPHRASE(_FILE) or a");
    eprintln!("confirmed prompt. Secrets are never printed.");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Strict parsing: a value flag captures its value, a switch registers, and
    /// anything unknown is refused rather than silently ignored.
    #[test]
    fn argument_parsing_is_strict() {
        let args: Vec<String> = ["--path", "/k.age", "--secret-stdin"]
            .iter()
            .map(ToString::to_string)
            .collect();
        let parsed = Args::parse(&args, &["--path"], &["--secret-stdin"]).expect("parse");
        assert_eq!(parsed.get("--path"), Some("/k.age"));
        assert!(parsed.has("--secret-stdin"));
        assert_eq!(parsed.get("--label"), None);

        let unknown: Vec<String> = ["--netwrok", "preprod"]
            .iter()
            .map(ToString::to_string)
            .collect();
        let err = Args::parse(&unknown, &["--network"], &[]).expect_err("typo must be refused");
        assert!(err.to_string().contains("--netwrok"), "got: {err}");

        let missing_value: Vec<String> = ["--path"].iter().map(ToString::to_string).collect();
        let err = Args::parse(&missing_value, &["--path"], &[]).expect_err("dangling flag");
        assert!(err.to_string().contains("requires a value"), "got: {err}");

        let twice: Vec<String> = ["--path", "/a", "--path", "/b"]
            .iter()
            .map(ToString::to_string)
            .collect();
        let err = Args::parse(&twice, &["--path"], &[]).expect_err("a repeated flag is ambiguous");
        assert!(err.to_string().contains("more than once"), "got: {err}");
    }

    /// An empty environment passphrase is refused with the variable named.
    #[test]
    fn an_empty_env_passphrase_is_refused() {
        let err = non_empty(
            Zeroizing::new(String::new()),
            config::KEYRING_PASSPHRASE_ENV,
        )
        .expect_err("empty must be refused");
        assert!(
            err.to_string().contains(config::KEYRING_PASSPHRASE_ENV),
            "got: {err}"
        );
    }
}
