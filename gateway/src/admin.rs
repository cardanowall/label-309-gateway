//! The `gateway admin …` subcommands: an HTTP client of the control plane.
//!
//! Every admin command is an HTTP request to the control plane, never a direct
//! database connection: the CLI drives exactly the contract a third party would,
//! so a working CLI proves the control API works. The configured base URL is the
//! FULL control-plane base including the version segment (e.g.
//! `http://127.0.0.1:8080/control/v1`); each command appends only its bare
//! resource suffix (`/accounts`, `/wallets/{id}/grants`, …). The base URL comes
//! from `--url` or the environment; the bearer credential (an operator token,
//! the root credential, or an account token) comes from the environment or a
//! stdin pipe (`--token-stdin`) only — never argv, which leaks into shell
//! history and process listings.
//!
//! Output is operator-friendly: a created secret is printed plainly (the API shows
//! it once), a list is rendered as compact rows, and a failure prints the API's
//! problem detail and exits non-zero.

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use zeroize::Zeroizing;

/// The environment variable carrying the control-plane base URL, including the
/// version segment (e.g. `http://127.0.0.1:8080/control/v1`).
pub const CONTROL_URL_ENV: &str = "GATEWAY_CONTROL_URL";

/// The environment variable carrying the bearer credential the CLI presents.
pub const CONTROL_TOKEN_ENV: &str = "GATEWAY_CONTROL_TOKEN";

/// The default control base URL when the environment does not set one. Carries the
/// version segment, like every configured base: each command appends only its bare
/// resource suffix.
const DEFAULT_CONTROL_URL: &str = "http://127.0.0.1:8080/control/v1";

/// The resolved bearer credential, held only in memory: zeroized on drop and
/// redacted from any `Debug` render so the secret cannot land in logs or panic
/// output. There is deliberately NO argv source — a token on argv leaks into
/// shell history and process listings — so the credential arrives via the
/// environment or a stdin pipe only.
struct BearerToken(Zeroizing<String>);

impl BearerToken {
    /// The plaintext, exposed only at the moment the Authorization header is
    /// built.
    fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for BearerToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BearerToken(<redacted>)")
    }
}

/// A resolved admin invocation: the HTTP client context plus the parsed command.
struct AdminClient {
    base_url: String,
    token: BearerToken,
    http: reqwest::blocking::Client,
}

impl AdminClient {
    /// Resolve the client context from flags and the environment.
    ///
    /// Token precedence is environment first, then `--token-stdin`. The
    /// environment variable is the recommended source, so it wins;
    /// `--token-stdin` reads the bearer off a pipe. Both keep the credential off
    /// argv; an argv `--token` flag no longer exists (it leaked the bearer into
    /// `ps` and shell history).
    fn resolve(flags: Flags) -> Result<Self> {
        let base_url = flags
            .url
            .clone()
            .or_else(|| std::env::var(CONTROL_URL_ENV).ok())
            .unwrap_or_else(|| DEFAULT_CONTROL_URL.to_string());
        let token = std::env::var(CONTROL_TOKEN_ENV)
            .ok()
            .map(Zeroizing::new)
            .filter(|t| !t.is_empty())
            .or(flags.token_stdin)
            .map(BearerToken)
            .with_context(|| {
                format!(
                    "a bearer credential is required (set {CONTROL_TOKEN_ENV}, or pipe it via --token-stdin)"
                )
            })?;
        let http = reqwest::blocking::Client::builder()
            .build()
            .context("building the HTTP client")?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            token,
            http,
        })
    }

    /// Issue a request to a control path, returning the parsed JSON body or an
    /// error carrying the API's problem detail.
    fn request(&self, method: reqwest::Method, path: &str, body: Option<Value>) -> Result<Value> {
        self.request_with_status(method, path, body)
            .map(|(_, value)| value)
    }

    /// Issue a request and also return the success status, for the commands whose
    /// output depends on it (the top-up create distinguishes 201 created from a
    /// 200 idempotent replay).
    fn request_with_status(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<(reqwest::StatusCode, Value)> {
        let url = format!("{}{path}", self.base_url);
        let mut req = self
            .http
            .request(method, &url)
            .bearer_auth(self.token.expose());
        if let Some(b) = body {
            req = req.json(&b);
        }
        let resp = req.send().with_context(|| format!("requesting {url}"))?;
        let status = resp.status();
        let value: Value = resp.json().unwrap_or(Value::Null);
        if status.is_success() {
            Ok((status, value))
        } else {
            let detail = value
                .get("detail")
                .and_then(|d| d.as_str())
                .unwrap_or("the control plane rejected the request");
            bail!("{} ({status})", detail)
        }
    }
}

/// The shared flags every admin command accepts.
#[derive(Default)]
struct Flags {
    url: Option<String>,
    /// The bearer read from stdin when `--token-stdin` is given. Kept off argv
    /// so the credential never appears in `ps`/shell history.
    token_stdin: Option<Zeroizing<String>>,
}

/// Parse the shared flags out of an argument list, returning the remaining
/// positional arguments and the resolved flags.
fn split_flags(args: &[String]) -> Result<(Vec<String>, Flags)> {
    let mut flags = Flags::default();
    let mut positional = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--url" => {
                flags.url = Some(
                    iter.next()
                        .cloned()
                        .ok_or_else(|| anyhow!("--url requires a value"))?,
                );
            }
            // The argv token flag is gone for good: a bearer on argv leaks into
            // shell history and process listings, and the two leak-free sources
            // already cover every invocation shape. Rejected explicitly (rather
            // than falling through as an unknown command) so an operator with an
            // old script gets the migration path, not a confusing usage error.
            "--token" => {
                bail!(
                    "--token was removed: a bearer on argv leaks into shell history and \
                     `ps` output. Set {CONTROL_TOKEN_ENV} or pipe the credential via \
                     --token-stdin instead"
                );
            }
            "--token-stdin" => {
                // Read the bearer off stdin, trimmed of the trailing newline a
                // here-string or `echo` adds, so the credential never rides argv.
                let mut raw = Zeroizing::new(String::new());
                std::io::Read::read_to_string(&mut std::io::stdin(), &mut raw)
                    .context("reading the bearer credential from stdin")?;
                let token = Zeroizing::new(raw.trim_end_matches(['\n', '\r']).to_string());
                if token.is_empty() {
                    bail!("--token-stdin was given but stdin carried no credential");
                }
                flags.token_stdin = Some(token);
            }
            other => positional.push(other.to_string()),
        }
    }
    Ok((positional, flags))
}

/// Run the `gateway admin …` command from its argument list (everything after
/// `admin`). Prints results to stdout and returns an error the caller surfaces as
/// a non-zero exit.
pub fn run(args: &[String]) -> Result<()> {
    let (positional, flags) = split_flags(args)?;
    let client = AdminClient::resolve(flags)?;

    let mut parts = positional.iter().map(String::as_str);
    let group = parts.next().unwrap_or("");
    let action = parts.next().unwrap_or("");
    let rest: Vec<&str> = parts.collect();

    match (group, action) {
        ("account", "create") => account_create(&client),
        ("account", "list") => account_list(&client),
        ("account", "disable") => account_status_change(&client, &rest, "disable"),
        ("account", "enable") => account_status_change(&client, &rest, "enable"),
        ("account", "fund") => account_fund(&client, &rest),
        ("account", "clamp-debit") => account_clamp_debit(&client, &rest),
        ("account", "usage") => account_usage(&client, &rest),
        ("account", "margin") => account_margin(&client, &rest),
        ("key", "create") => key_create(&client, &rest),
        ("key", "list") => key_list(&client, &rest),
        ("key", "revoke") => key_revoke(&client, &rest),
        ("key", "relabel") => key_relabel(&client, &rest),
        ("credential", "rotate-root") => credential_rotate_root(&client, &rest),
        ("credential", "list") => credential_list(&client),
        ("credential", "revoke") => credential_revoke(&client, &rest),
        ("wallet", "list") => wallet_list(&client),
        ("wallet", "operator-balance") => wallet_operator_balance(&client),
        ("wallet", "drain") => wallet_transition(&client, &rest, "drain"),
        ("wallet", "reactivate") => wallet_transition(&client, &rest, "reactivate"),
        ("wallet", "register") => wallet_register(&client, &rest),
        ("wallet", "grant") => wallet_grant(&client, &rest),
        ("wallet", "grant-revoke") => wallet_grant_revoke(&client, &rest),
        ("storage", "source") => storage_source(&client, &rest),
        ("storage", "sources") => storage_sources_list(&client),
        ("storage", "top-up") => storage_topup(&client, &rest),
        ("storage", "top-up-register") => storage_topup_register(&client, &rest),
        ("storage", "top-ups") => storage_topups_list(&client),
        ("storage", "funding") => storage_funding(&client),
        ("storage", "operator-balance") => storage_operator_balance(&client),
        ("chain", "provider-usage") => chain_provider_usage(&client, &rest),
        ("pricing", "fx") => pricing_fx(&client),
        ("webhook", "health") => webhook_health(&client),
        ("webhook", "create") => webhook_create(&client, &rest),
        ("webhook", "list") => webhook_list(&client),
        ("webhook", "get") => webhook_get(&client, &rest),
        ("webhook", "update") => webhook_update(&client, &rest),
        ("webhook", "delete") => webhook_delete(&client, &rest),
        ("webhook", "rotate-secret") => webhook_rotate_secret(&client, &rest),
        ("webhook", "rotate-secret-commit") => webhook_rotate_secret_commit(&client, &rest),
        ("webhook", "deliveries") => webhook_deliveries(&client, &rest),
        ("webhook", "delivery-retry") => webhook_delivery_retry(&client, &rest),
        ("token", "mint") => token_mint(&client, &rest),
        ("token", "list") => token_list(&client),
        ("token", "revoke") => token_revoke(&client, &rest),
        ("audit", "tail") => audit_tail(&client, &rest),
        _ => {
            print_usage();
            bail!("unknown admin command: {group} {action}")
        }
    }
}

// ---------------------------------------------------------------------------
// Accounts.
// ---------------------------------------------------------------------------

fn account_create(client: &AdminClient) -> Result<()> {
    let body = client.request(reqwest::Method::POST, "/accounts", None)?;
    println!("account created: {}", field(&body, "account_id"));
    Ok(())
}

fn account_list(client: &AdminClient) -> Result<()> {
    let body = client.request(reqwest::Method::GET, "/accounts", None)?;
    render_list(&body, "accounts", |row| {
        println!(
            "{}  {}  balance={} micros",
            field(row, "account_id"),
            field(row, "status"),
            field(row, "balance_usd_micros"),
        );
    });
    Ok(())
}

fn account_status_change(client: &AdminClient, rest: &[&str], action: &str) -> Result<()> {
    let account_id = positional_arg(rest, 0, "account_id")?;
    let path = format!("/accounts/{account_id}/{action}");
    let body = client.request(reqwest::Method::POST, &path, Some(json!({})))?;
    println!(
        "account {} -> {} (changed={})",
        account_id,
        field(&body, "status"),
        field(&body, "changed"),
    );
    Ok(())
}

fn account_fund(client: &AdminClient, rest: &[&str]) -> Result<()> {
    let account_id = positional_arg(rest, 0, "account_id")?;
    let amount: i64 = positional_arg(rest, 1, "amount_usd_micros")?
        .parse()
        .context("amount_usd_micros must be an integer")?;
    let reason = positional_arg(rest, 2, "reason")?;
    let path = format!("/accounts/{account_id}/ledger-adjustment");
    let body = client.request(
        reqwest::Method::POST,
        &path,
        Some(json!({ "amount_usd_micros": amount, "reason": reason })),
    )?;
    println!(
        "adjusted account {} by {} micros (applied={})",
        account_id,
        amount,
        field(&body, "applied"),
    );
    Ok(())
}

/// `account clamp-debit <account_id> <amount_usd_micros> <reason> <ref>` — debit a
/// balance toward zero by up to an amount, clamped at the available balance.
///
/// The clawback primitive: it removes only what the balance can cover and reports
/// what it actually took. `ref` is required (the originating clawback id); a
/// redelivery with the same ref returns the same debited amount with `applied=false`.
fn account_clamp_debit(client: &AdminClient, rest: &[&str]) -> Result<()> {
    let account_id = positional_arg(rest, 0, "account_id")?;
    let amount: i64 = positional_arg(rest, 1, "amount_usd_micros")?
        .parse()
        .context("amount_usd_micros must be an integer")?;
    let reason = positional_arg(rest, 2, "reason")?;
    let reference = positional_arg(rest, 3, "ref")?;
    let path = format!("/accounts/{account_id}/ledger-clamp-debit");
    let body = client.request(
        reqwest::Method::POST,
        &path,
        Some(json!({ "amount_usd_micros": amount, "reason": reason, "ref": reference })),
    )?;
    println!(
        "clamp-debit account {} debited {} micros (applied={})",
        account_id,
        field(&body, "debited_usd_micros"),
        field(&body, "applied"),
    );
    Ok(())
}

/// `account usage <account_id>` — the account's status, balance, and usage counters.
fn account_usage(client: &AdminClient, rest: &[&str]) -> Result<()> {
    let account_id = positional_arg(rest, 0, "account_id")?;
    let path = format!("/accounts/{account_id}/usage");
    let body = client.request(reqwest::Method::GET, &path, None)?;
    println!(
        "account {}  status={}  balance={} micros",
        account_id,
        field(&body, "status"),
        field(&body, "balance_usd_micros"),
    );
    println!(
        "  ledger_entries={}  quotes={}  publishes={}",
        field(&body, "ledger_entry_count"),
        field(&body, "quote_count"),
        field(&body, "publish_count"),
    );
    Ok(())
}

/// Dispatch the `account margin <set|unset> …` subcommands: the per-account markup
/// override the pricing seam applies on top of the operator default.
fn account_margin(client: &AdminClient, rest: &[&str]) -> Result<()> {
    let action = rest.first().copied().unwrap_or("");
    let tail = rest.get(1..).unwrap_or(&[]);
    match action {
        "set" => account_margin_set(client, tail),
        "unset" => account_margin_unset(client, tail),
        other => {
            print_usage();
            bail!("unknown admin command: account margin {other}")
        }
    }
}

/// `account margin set <account_id> <margin_pct>` — set (or replace) the override.
/// `margin_pct` is a non-negative decimal fraction (e.g. `0.25` = 25%).
fn account_margin_set(client: &AdminClient, rest: &[&str]) -> Result<()> {
    let account_id = positional_arg(rest, 0, "account_id")?;
    let raw = positional_arg(rest, 1, "margin_pct (a fraction, e.g. 0.25)")?;
    // Send the fraction as a JSON number, the shape the margin route deserializes;
    // parsing it here rejects a non-numeric argument before any HTTP call.
    let margin: Value = serde_json::from_str(raw)
        .ok()
        .filter(Value::is_number)
        .with_context(|| {
            format!("margin_pct must be a decimal fraction, e.g. 0.25 (got {raw:?})")
        })?;
    let path = format!("/accounts/{account_id}/margin");
    let body = client.request(
        reqwest::Method::PUT,
        &path,
        Some(json!({ "margin_pct": margin })),
    )?;
    println!(
        "account {} margin set to {} (source={})",
        account_id,
        field(&body, "margin_pct"),
        field(&body, "margin_source"),
    );
    Ok(())
}

/// `account margin unset <account_id>` — clear the override, reverting the account to
/// the operator-default margin. Idempotent (`cleared=false` when none was present).
fn account_margin_unset(client: &AdminClient, rest: &[&str]) -> Result<()> {
    let account_id = positional_arg(rest, 0, "account_id")?;
    let path = format!("/accounts/{account_id}/margin");
    let body = client.request(reqwest::Method::DELETE, &path, None)?;
    println!(
        "account {} margin cleared={} (source={})",
        account_id,
        field(&body, "cleared"),
        field(&body, "margin_source"),
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Keys.
// ---------------------------------------------------------------------------

fn key_create(client: &AdminClient, rest: &[&str]) -> Result<()> {
    let account_id = positional_arg(rest, 0, "account_id")?;
    let scopes_csv = positional_arg(rest, 1, "scopes (comma-separated)")?;
    // The per-minute budget is optional: when absent the field is omitted from
    // the body entirely and the gateway meters the key against its data-plane
    // default budget.
    let rate_limit: Option<i32> = rest
        .get(2)
        .map(|s| s.parse())
        .transpose()
        .context("rate_limit_per_min must be an integer")?;
    let scopes: Vec<&str> = scopes_csv.split(',').filter(|s| !s.is_empty()).collect();
    let mut payload = json!({ "scopes": scopes });
    if let Some(rate) = rate_limit {
        payload["rate_limit_per_min"] = json!(rate);
    }
    let path = format!("/accounts/{account_id}/keys");
    let body = client.request(reqwest::Method::POST, &path, Some(payload))?;
    println!("key created: {}", field(&body, "key_id"));
    // The API shows the secret once; surface it plainly so the operator can copy it.
    println!("secret (shown once): {}", field(&body, "secret"));
    Ok(())
}

fn key_list(client: &AdminClient, rest: &[&str]) -> Result<()> {
    let account_id = positional_arg(rest, 0, "account_id")?;
    let path = format!("/accounts/{account_id}/keys");
    let body = client.request(reqwest::Method::GET, &path, None)?;
    render_list(&body, "keys", |row| {
        println!(
            "{}  scopes={}  revoked_at={}",
            field(row, "key_id"),
            field(row, "scopes"),
            field(row, "revoked_at"),
        );
    });
    Ok(())
}

fn key_revoke(client: &AdminClient, rest: &[&str]) -> Result<()> {
    let account_id = positional_arg(rest, 0, "account_id")?;
    let key_id = positional_arg(rest, 1, "key_id")?;
    let path = format!("/accounts/{account_id}/keys/{key_id}/revoke");
    let body = client.request(reqwest::Method::POST, &path, Some(json!({})))?;
    println!("key {} revoked={}", key_id, field(&body, "revoked"));
    Ok(())
}

/// `key relabel <account_id> <key_id> [label]` — set or clear a key's human label.
/// Omitting the label clears it.
fn key_relabel(client: &AdminClient, rest: &[&str]) -> Result<()> {
    let account_id = positional_arg(rest, 0, "account_id")?;
    let key_id = positional_arg(rest, 1, "key_id")?;
    let body = rest.get(2).map(|label| json!({ "label": label }));
    let path = format!("/accounts/{account_id}/keys/{key_id}/relabel");
    let response = client.request(reqwest::Method::POST, &path, body)?;
    println!("key {} relabeled={}", key_id, field(&response, "relabeled"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Control credentials (root rotation / revocation).
// ---------------------------------------------------------------------------

/// `credential rotate-root [label]` — rotate the presented root credential.
///
/// Root-gated server-side: the rotation replaces the exact credential the CLI
/// presents, revoking it and minting its successor in one transaction. The
/// successor's secret is printed exactly once, with the same care framing the
/// bootstrap print uses — it is never stored and cannot be recovered. The
/// high-authority root bearer arrives via the GATEWAY_CONTROL_TOKEN env var or
/// a stdin pipe, like every credential (there is no argv token source).
fn credential_rotate_root(client: &AdminClient, rest: &[&str]) -> Result<()> {
    let body = rest.first().map(|label| json!({ "label": label }));
    let response = client.request(reqwest::Method::POST, "/operator/root/rotate", body)?;
    println!("root credential rotated");
    println!(
        "  credential_id          {}",
        field(&response, "credential_id")
    );
    println!(
        "  revoked_credential_id  {}",
        field(&response, "revoked_credential_id")
    );
    println!();
    println!("  new operator root secret (shown once, store it now):");
    println!();
    println!("    {}", field(&response, "secret"));
    println!();
    println!("  This secret is not stored and cannot be recovered. The old root and");
    println!("  every operator/account token minted under it are now revoked; mint");
    println!("  fresh operator tokens with `gateway admin token mint operator`.");
    Ok(())
}

/// `credential list` — the operator's control-credential roster (ids and
/// lifecycle only; secrets are unrecoverable by design).
fn credential_list(client: &AdminClient) -> Result<()> {
    let body = client.request(reqwest::Method::GET, "/credentials", None)?;
    render_list(&body, "credentials", |row| {
        println!(
            "{}  {}  label={}  created_at={}  revoked_at={}",
            field(row, "credential_id"),
            field(row, "kind"),
            field(row, "label"),
            field(row, "created_at"),
            field(row, "revoked_at"),
        );
    });
    Ok(())
}

/// `credential revoke <credential_id>` — revoke a control credential. Root-gated
/// server-side; revoking the last live root is refused (rotate instead).
fn credential_revoke(client: &AdminClient, rest: &[&str]) -> Result<()> {
    let credential_id = positional_arg(rest, 0, "credential_id")?;
    let path = format!("/credentials/{credential_id}/revoke");
    let body = client.request(reqwest::Method::POST, &path, Some(json!({})))?;
    println!(
        "credential {} revoked={}",
        credential_id,
        field(&body, "revoked"),
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Wallets.
// ---------------------------------------------------------------------------

fn wallet_list(client: &AdminClient) -> Result<()> {
    let body = client.request(reqwest::Method::GET, "/wallets", None)?;
    render_list(&body, "wallets", |row| {
        println!(
            "{}  {}  {}  available={} canonical={}",
            field(row, "wallet_id"),
            field(row, "status"),
            field(row, "address"),
            field(row, "available_utxos"),
            field(row, "canonical_utxos"),
        );
    });
    Ok(())
}

/// `wallet operator-balance` — the LIVE on-chain ADA balance per Cardano signing
/// wallet (a balance overlay keyed by wallet id; join it onto `wallet list` for the
/// wallet's identity fields). Degrades gracefully: a deployment with no chain seam
/// reports `chain_configured=false`, and an unreachable provider lands as a
/// per-wallet error while every other wallet's balance still serves.
fn wallet_operator_balance(client: &AdminClient) -> Result<()> {
    let body = client.request(reqwest::Method::GET, "/wallets/operator-balance", None)?;
    println!("chain_configured={}", field(&body, "chain_configured"));
    for row in body
        .get("balances")
        .and_then(|b| b.as_array())
        .map(|a| a.iter().collect::<Vec<_>>())
        .unwrap_or_default()
    {
        match row.get("balance_error").and_then(|e| e.as_str()) {
            Some(err) => println!("{}  balance unavailable: {}", field(row, "wallet_id"), err),
            None => println!(
                "{}  balance_lovelace={}",
                field(row, "wallet_id"),
                field(row, "balance_lovelace"),
            ),
        }
    }
    Ok(())
}

fn wallet_transition(client: &AdminClient, rest: &[&str], action: &str) -> Result<()> {
    let wallet_id = positional_arg(rest, 0, "wallet_id")?;
    let path = format!("/wallets/{wallet_id}/{action}");
    let body = client.request(reqwest::Method::POST, &path, Some(json!({})))?;
    println!(
        "wallet {} -> {} (changed={})",
        wallet_id,
        field(&body, "status"),
        field(&body, "changed"),
    );
    Ok(())
}

/// `wallet register <label> <address> <network> [scope] [scope_account_id]` —
/// register a keyring-backed wallet and auto-issue its spend grant.
///
/// This route is root-gated server-side: registration binds a shared-keyring
/// signing key to an owning operator, so only the operator root may claim it. The
/// CLI carries no client-side authority logic — it forwards whatever bearer
/// resolved and lets `authorize_root` decide; a non-root credential is surfaced as
/// the route's 403. The high-authority root bearer arrives via the
/// GATEWAY_CONTROL_TOKEN env var or a stdin pipe, like every credential (an argv
/// token source no longer exists — it leaked into shell history and `ps`).
fn wallet_register(client: &AdminClient, rest: &[&str]) -> Result<()> {
    let label = positional_arg(rest, 0, "label")?;
    let address = positional_arg(rest, 1, "address")?;
    let network = positional_arg(rest, 2, "network")?;
    let mut body = json!({ "label": label, "address": address, "network": network });
    if let Some(scope) = rest.get(3) {
        body["scope"] = json!(scope);
    }
    if let Some(scope_account_id) = rest.get(4) {
        body["scope_account_id"] = json!(scope_account_id);
    }
    let response = client.request(reqwest::Method::POST, "/wallets", Some(body))?;
    println!(
        "wallet {} registered (created={}) grant {}",
        field(&response, "wallet_id"),
        field(&response, "created"),
        field(&response, "grant_id"),
    );
    Ok(())
}

/// `wallet grant <wallet_id> <service|operator|account> [account_id]` — issue a
/// spend grant on a registered wallet. Operator-gated server-side (the wallet's
/// registrar). An `account` scope requires the account id.
fn wallet_grant(client: &AdminClient, rest: &[&str]) -> Result<()> {
    let wallet_id = positional_arg(rest, 0, "wallet_id")?;
    let body = grant_body(rest)?;
    let path = format!("/wallets/{wallet_id}/grants");
    let response = client.request(reqwest::Method::POST, &path, Some(body))?;
    println!(
        "grant {} on wallet {} (issued={})",
        field(&response, "grant_id"),
        field(&response, "wallet_id"),
        field(&response, "issued"),
    );
    Ok(())
}

/// `wallet grant-revoke <wallet_id> <grant_id>` — revoke a spend grant. A soft
/// revoke (idempotent); gates new picks only, in-flight submits still settle.
fn wallet_grant_revoke(client: &AdminClient, rest: &[&str]) -> Result<()> {
    let wallet_id = positional_arg(rest, 0, "wallet_id")?;
    let grant_id = positional_arg(rest, 1, "grant_id")?;
    let path = format!("/wallets/{wallet_id}/grants/{grant_id}/revoke");
    let response = client.request(reqwest::Method::POST, &path, Some(json!({})))?;
    println!(
        "grant {} on wallet {} revoked={}",
        grant_id,
        wallet_id,
        field(&response, "revoked"),
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Storage funding sources.
// ---------------------------------------------------------------------------

/// Dispatch the `storage source <action> …` subcommands, the funding-source twin
/// of the wallet register/grant/grant-revoke surface.
fn storage_source(client: &AdminClient, rest: &[&str]) -> Result<()> {
    let action = rest.first().copied().unwrap_or("");
    let tail = rest.get(1..).unwrap_or(&[]);
    match action {
        "register" => storage_source_register(client, tail),
        "grant" => storage_source_grant(client, tail),
        "grant-revoke" => storage_source_grant_revoke(client, tail),
        "drain" => storage_source_drain(client, tail),
        other => {
            print_usage();
            bail!("unknown admin command: storage source {other}")
        }
    }
}

/// `storage sources` — list the operator's funding sources with their cached credit
/// diagnostics and a staleness flag.
fn storage_sources_list(client: &AdminClient) -> Result<()> {
    let body = client.request(reqwest::Method::GET, "/storage/sources", None)?;
    render_list(&body, "storage funding sources", |row| {
        println!(
            "{}  {}  {}  backend={}  winc={}  fundable_bytes={}  stale={}  last_error={}",
            field(row, "source_id"),
            field(row, "status"),
            field(row, "arweave_address"),
            field(row, "backend"),
            field(row, "winc_balance"),
            field(row, "fundable_bytes"),
            field(row, "stale"),
            field(row, "last_error"),
        );
    });
    Ok(())
}

/// `storage source drain <source_id>` — transition a funding source active ->
/// draining: it takes no new charges while in-flight uploads settle by source id.
/// Operator-gated (the source's owner). Idempotent.
fn storage_source_drain(client: &AdminClient, rest: &[&str]) -> Result<()> {
    let source_id = positional_arg(rest, 0, "source_id")?;
    let path = format!("/storage/sources/{source_id}/drain");
    let response = client.request(reqwest::Method::POST, &path, Some(json!({})))?;
    println!(
        "source {} -> {} (changed={})",
        source_id,
        field(&response, "status"),
        field(&response, "changed"),
    );
    Ok(())
}

/// `storage source register <label> <backend> <address> [scope] [scope_account_id]`
/// — register a keyring-backed Arweave funding source and auto-issue its draw
/// grant. Root-gated server-side (binds a shared-keyring key to an owner); the
/// root credential arrives via GATEWAY_CONTROL_TOKEN or a stdin pipe, same as the
/// wallet register.
fn storage_source_register(client: &AdminClient, rest: &[&str]) -> Result<()> {
    let label = positional_arg(rest, 0, "label")?;
    let backend = positional_arg(rest, 1, "backend")?;
    let address = positional_arg(rest, 2, "address")?;
    let mut body = json!({ "label": label, "backend": backend, "address": address });
    if let Some(scope) = rest.get(3) {
        body["scope"] = json!(scope);
    }
    if let Some(scope_account_id) = rest.get(4) {
        body["scope_account_id"] = json!(scope_account_id);
    }
    let response = client.request(reqwest::Method::POST, "/storage/sources", Some(body))?;
    println!(
        "source {} registered (created={}) grant {}",
        field(&response, "source_id"),
        field(&response, "created"),
        field(&response, "grant_id"),
    );
    Ok(())
}

/// `storage source grant <source_id> <service|operator|account> [account_id]` —
/// issue a draw grant on a registered source. Operator-gated server-side.
fn storage_source_grant(client: &AdminClient, rest: &[&str]) -> Result<()> {
    let source_id = positional_arg(rest, 0, "source_id")?;
    let body = grant_body(rest)?;
    let path = format!("/storage/sources/{source_id}/grants");
    let response = client.request(reqwest::Method::POST, &path, Some(body))?;
    println!(
        "grant {} on source {} (issued={})",
        field(&response, "grant_id"),
        field(&response, "source_id"),
        field(&response, "issued"),
    );
    Ok(())
}

/// `storage source grant-revoke <source_id> <grant_id>` — revoke a draw grant. A
/// soft revoke (idempotent); gates new charges only, in-flight uploads still settle.
fn storage_source_grant_revoke(client: &AdminClient, rest: &[&str]) -> Result<()> {
    let source_id = positional_arg(rest, 0, "source_id")?;
    let grant_id = positional_arg(rest, 1, "grant_id")?;
    let path = format!("/storage/sources/{source_id}/grants/{grant_id}/revoke");
    let response = client.request(reqwest::Method::POST, &path, Some(json!({})))?;
    println!(
        "grant {} on source {} revoked={}",
        grant_id,
        source_id,
        field(&response, "revoked"),
    );
    Ok(())
}

/// Build the `{ scope, account_id? }` body shared by the wallet and storage-source
/// grant commands. The scope is the second positional (index 1, after the resource
/// id); an `account` scope carries the named account id as the third positional.
fn grant_body(rest: &[&str]) -> Result<Value> {
    let scope = positional_arg(rest, 1, "scope (service|operator|account)")?;
    let mut body = json!({ "scope": scope });
    if scope == "account" {
        let account_id = positional_arg(rest, 2, "account_id (required for an account scope)")?;
        body["account_id"] = json!(account_id);
    }
    Ok(body)
}

// ---------------------------------------------------------------------------
// The storage funding console: balances, the conversion journal, and the
// AR -> credit top-up.
// ---------------------------------------------------------------------------

/// `storage top-up <ar_amount_winston> <idempotency_key> [funding_source_id]` —
/// convert AR from the operator's funding wallet into prepaid provider credits.
///
/// The conversion is an IRREVERSIBLE on-chain fund movement, so the create is
/// idempotent on the required key: retrying a lost response with the same key
/// replays the journalled conversion (200) instead of signing a second
/// transfer; only a genuinely new key signs and returns 201. The source is
/// optional when the operator owns exactly one active source on the backend.
fn storage_topup(client: &AdminClient, rest: &[&str]) -> Result<()> {
    let ar_amount_winston = positional_arg(rest, 0, "ar_amount_winston")?;
    let idempotency_key = positional_arg(rest, 1, "idempotency_key")?;
    let mut body = json!({
        "ar_amount_winston": ar_amount_winston,
        "idempotency_key": idempotency_key,
    });
    if let Some(source_id) = rest.get(2) {
        body["funding_source_id"] = json!(source_id);
    }
    let (status, response) =
        client.request_with_status(reqwest::Method::POST, "/storage/top-up", Some(body))?;
    let outcome = if status == reqwest::StatusCode::CREATED {
        "created"
    } else {
        "replayed (this idempotency key already named a conversion)"
    };
    println!("top-up {} {outcome}", field(&response, "topup_id"));
    println!("  status        {}", field(&response, "status"));
    println!("  ar (winston)  {}", field(&response, "ar_amount_winston"));
    println!("  fee (winston) {}", field(&response, "fee_winston"));
    println!("  tx_id         {}", field(&response, "tx_id"));
    println!("  winc          {}", field(&response, "registered_winc"));
    if let Some(err) = response.get("last_error").and_then(|e| e.as_str()) {
        println!("  last_error    {err}");
        println!();
        println!(
            "  The transfer is journalled; retry it FORWARD with `gateway admin storage \
             top-up-register {}` (or repeat this exact command with the same key) — \
             never with a new key, which would sign a second transfer.",
            field(&response, "topup_id")
        );
    } else {
        println!();
        println!(
            "  Reusing the same idempotency key replays this conversion; use a fresh \
             key (e.g. a UUID) for the next top-up."
        );
    }
    Ok(())
}

/// `storage top-up-register <topup_id>` — retry an unfinished top-up FORWARD:
/// re-broadcast the persisted transfer if unconfirmed, then re-register the same
/// transaction with the payment service. Never re-signs. Idempotent once
/// registered.
fn storage_topup_register(client: &AdminClient, rest: &[&str]) -> Result<()> {
    let topup_id = positional_arg(rest, 0, "topup_id")?;
    let path = format!("/storage/top-ups/{topup_id}/register");
    let response = client.request(reqwest::Method::POST, &path, Some(json!({})))?;
    println!(
        "top-up {} -> {} (winc={})",
        field(&response, "topup_id"),
        field(&response, "status"),
        field(&response, "registered_winc"),
    );
    Ok(())
}

/// `storage top-ups` — the operator's AR -> credit conversion journal,
/// newest-first.
fn storage_topups_list(client: &AdminClient) -> Result<()> {
    let body = client.request(reqwest::Method::GET, "/storage/top-ups", None)?;
    render_list(&body, "top-ups", |row| {
        println!(
            "{}  {}  ar={} winston  winc={}  tx={}  created_at={}  last_error={}",
            field(row, "topup_id"),
            field(row, "status"),
            field(row, "ar_amount_winston"),
            field(row, "registered_winc"),
            field(row, "tx_id"),
            field(row, "created_at"),
            field(row, "last_error"),
        );
    });
    Ok(())
}

/// `storage funding` — the cached aggregate funding status across the
/// operator's sources (no provider call).
fn storage_funding(client: &AdminClient) -> Result<()> {
    let body = client.request(reqwest::Method::GET, "/storage/funding", None)?;
    println!(
        "sources={}  total_winc={}  total_fundable_bytes={}  stale_sources={}",
        field(&body, "source_count"),
        field(&body, "total_winc_balance"),
        field(&body, "total_fundable_bytes"),
        field(&body, "stale_source_count"),
    );
    Ok(())
}

/// `storage operator-balance` — the LIVE storage funding position: per funding
/// wallet, the on-chain AR balance and (on a Turbo backend) the live prepaid
/// winc balance, plus whether a top-up can be issued right now.
fn storage_operator_balance(client: &AdminClient) -> Result<()> {
    let body = client.request(reqwest::Method::GET, "/storage/operator-balance", None)?;
    println!(
        "storage_configured={}  backend={}",
        field(&body, "storage_configured"),
        field(&body, "backend"),
    );
    for wallet in body
        .get("wallets")
        .and_then(|w| w.as_array())
        .map(|a| a.iter().collect::<Vec<_>>())
        .unwrap_or_default()
    {
        let turbo = wallet.get("turbo").cloned().unwrap_or(Value::Null);
        let turbo_display = if turbo.get("available").and_then(|a| a.as_bool()) == Some(true) {
            format!(
                "winc={} fundable_bytes={}",
                field(&turbo, "winc"),
                field(&turbo, "fundable_bytes"),
            )
        } else {
            format!("unavailable ({})", field(&turbo, "reason"))
        };
        println!(
            "{}  ar_winston={}  turbo: {}",
            field(wallet, "arweave_address"),
            field(wallet, "ar_balance_winston"),
            turbo_display,
        );
        if let Some(err) = wallet.get("ar_balance_error").and_then(|e| e.as_str()) {
            println!("  ar balance unavailable: {err}");
        }
    }
    let top_up = body.get("top_up").cloned().unwrap_or(Value::Null);
    if top_up.get("enabled").and_then(|e| e.as_bool()) == Some(true) {
        println!("top-up: enabled");
    } else {
        println!("top-up: disabled ({})", field(&top_up, "reason"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Chain-provider usage and the live FX snapshot.
// ---------------------------------------------------------------------------

/// `chain provider-usage [days]` — the per-day chain-provider request counts the
/// egress gate records (default 7 trailing UTC days). A non-zero `denied` count means
/// the local egress backstop fired and is worth investigating. A pure cached read.
fn chain_provider_usage(client: &AdminClient, rest: &[&str]) -> Result<()> {
    // Validate the window locally so a non-numeric argument fails before the call.
    let days: Option<i64> = rest
        .first()
        .map(|s| s.parse())
        .transpose()
        .context("days must be an integer")?;
    let path = match days {
        Some(d) => format!("/chain/provider-usage?days={d}"),
        None => "/chain/provider-usage".to_string(),
    };
    let body = client.request(reqwest::Method::GET, &path, None)?;
    render_list(&body, "chain provider usage", |row| {
        println!(
            "{}  {}  {}  requests={}  denied={}",
            field(row, "day"),
            field(row, "provider"),
            field(row, "network"),
            field(row, "request_count"),
            field(row, "denied_count"),
        );
    });
    Ok(())
}

/// `pricing fx` — the live FX snapshot every publish is priced from, plus how fresh
/// it is. A pure cached-row read (no oracle call). Before the refresh loop has
/// written its first row the snapshot reports unavailable rather than erroring.
fn pricing_fx(client: &AdminClient) -> Result<()> {
    let body = client.request(reqwest::Method::GET, "/pricing/fx", None)?;
    if body.get("available").and_then(|a| a.as_bool()) == Some(true) {
        println!(
            "fx available  stale={}  age={}s  source={}",
            field(&body, "stale"),
            field(&body, "age_seconds"),
            field(&body, "source"),
        );
        println!(
            "  ada_usd_micros={}  ar_usd_per_mib={}  fetched_at={}",
            field(&body, "ada_usd_micros"),
            field(&body, "ar_usd_per_mib"),
            field(&body, "fetched_at"),
        );
    } else {
        println!(
            "fx unavailable (no snapshot yet; live pricing has not started)  stale={}",
            field(&body, "stale"),
        );
    }
    println!(
        "  freshness_ceiling={}s  operator_default_margin_pct={}",
        field(&body, "freshness_ceiling_seconds"),
        field(&body, "operator_default_margin_pct"),
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Webhook firehose (operator-scoped subscriptions).
// ---------------------------------------------------------------------------

/// `webhook health` — the per-endpoint delivery-health summary across the operator's
/// firehose subscriptions, worst-first (a degrading endpoint is visible without
/// scanning its deliveries). A cached aggregate read; no delivery is attempted.
fn webhook_health(client: &AdminClient) -> Result<()> {
    let body = client.request(reqwest::Method::GET, "/webhooks/health", None)?;
    render_list(&body, "webhook subscriptions", |row| {
        println!(
            "{}  {}  {}  consecutive_failures={}  dead={}  pending={}  last_success_at={}",
            field(row, "endpoint_id"),
            field(row, "scope_kind"),
            field(row, "status"),
            field(row, "consecutive_failures"),
            field(row, "dead_deliveries"),
            field(row, "pending_deliveries"),
            field(row, "last_success_at"),
        );
    });
    Ok(())
}

/// `webhook create <url> [events,csv] [label]` — register an operator-scoped firehose
/// subscription. An omitted/empty event list subscribes to every event. The signing
/// secret is returned exactly once.
fn webhook_create(client: &AdminClient, rest: &[&str]) -> Result<()> {
    let url = positional_arg(rest, 0, "url")?;
    let events: Vec<&str> = rest
        .get(1)
        .map(|s| s.split(',').filter(|s| !s.is_empty()).collect())
        .unwrap_or_default();
    let mut payload = json!({ "url": url, "enabled_events": events });
    if let Some(label) = rest.get(2) {
        payload["label"] = json!(label);
    }
    let response = client.request(reqwest::Method::POST, "/webhooks", Some(payload))?;
    println!("webhook created: {}", field(&response, "id"));
    // The API shows the signing secret once; surface it plainly so the operator can copy it.
    println!("secret (shown once): {}", field(&response, "secret"));
    Ok(())
}

/// `webhook list` — the operator's firehose subscriptions (fingerprint only, never
/// the secret), newest first.
fn webhook_list(client: &AdminClient) -> Result<()> {
    let body = client.request(reqwest::Method::GET, "/webhooks", None)?;
    render_list(&body, "webhooks", |row| {
        println!(
            "{}  {}  {}  events={}  secret_fp={}  label={}",
            field(row, "id"),
            field(row, "status"),
            field(row, "url"),
            field(row, "enabled_events"),
            field(row, "secret_fp"),
            field(row, "label"),
        );
    });
    Ok(())
}

/// `webhook get <id>` — read one firehose subscription.
fn webhook_get(client: &AdminClient, rest: &[&str]) -> Result<()> {
    let id = positional_arg(rest, 0, "id")?;
    let path = format!("/webhooks/{id}");
    let body = client.request(reqwest::Method::GET, &path, None)?;
    println!(
        "{}  {}  {}",
        field(&body, "id"),
        field(&body, "status"),
        field(&body, "url"),
    );
    println!("  enabled_events={}", field(&body, "enabled_events"));
    println!(
        "  secret_fp={}  secret_next_fp={}",
        field(&body, "secret_fp"),
        field(&body, "secret_next_fp"),
    );
    println!(
        "  consecutive_failures={}  dead_deliveries={}  last_success_at={}",
        field(&body, "consecutive_failures"),
        field(&body, "dead_deliveries"),
        field(&body, "last_success_at"),
    );
    println!(
        "  label={}  created_at={}  updated_at={}",
        field(&body, "label"),
        field(&body, "created_at"),
        field(&body, "updated_at"),
    );
    Ok(())
}

/// `webhook update <id> <field> <value>` — patch one field of a firehose
/// subscription; call once per field to change several. `field` is `status`
/// (`active`|`paused`), `events` (a comma-separated filter; empty = all), `url`, or
/// `label` (a bare `-` clears it).
fn webhook_update(client: &AdminClient, rest: &[&str]) -> Result<()> {
    let id = positional_arg(rest, 0, "id")?;
    let field_name = positional_arg(rest, 1, "field (status|events|url|label)")?;
    let value = positional_arg(rest, 2, "value")?;
    let patch = webhook_patch_body(field_name, value)?;
    let path = format!("/webhooks/{id}");
    let body = client.request(reqwest::Method::PATCH, &path, Some(patch))?;
    println!(
        "webhook {} updated -> status={} url={}",
        field(&body, "id"),
        field(&body, "status"),
        field(&body, "url"),
    );
    Ok(())
}

/// `webhook delete <id>` — soft-delete a firehose subscription (204 on success).
fn webhook_delete(client: &AdminClient, rest: &[&str]) -> Result<()> {
    let id = positional_arg(rest, 0, "id")?;
    let path = format!("/webhooks/{id}");
    // A soft-delete returns 204 No Content; the request helper treats any 2xx as
    // success, so an empty body is fine.
    client.request(reqwest::Method::DELETE, &path, None)?;
    println!("webhook {id} deleted");
    Ok(())
}

/// `webhook rotate-secret <id>` — open a rotation window: mint a successor signing
/// secret (returned once) alongside the current one so a receiver can roll over
/// without dropping deliveries. Close the window with `webhook rotate-secret-commit`.
fn webhook_rotate_secret(client: &AdminClient, rest: &[&str]) -> Result<()> {
    let id = positional_arg(rest, 0, "id")?;
    let path = format!("/webhooks/{id}/rotate-secret");
    let body = client.request(reqwest::Method::POST, &path, Some(json!({})))?;
    println!("webhook {id} rotation window open");
    println!("  secret_fp       {}", field(&body, "secret_fp"));
    println!("  secret_next_fp  {}", field(&body, "secret_next_fp"));
    println!(
        "  successor secret (shown once): {}",
        field(&body, "secret_next"),
    );
    println!();
    println!("  Roll receivers onto the successor, then close the window with");
    println!("  `gateway admin webhook rotate-secret-commit {id}`.");
    Ok(())
}

/// `webhook rotate-secret-commit <id>` — close a rotation window: promote the
/// successor secret to primary and drop back to a single signing secret. A commit
/// with no open window is a 404 (nothing to promote), so it never clears the only secret.
fn webhook_rotate_secret_commit(client: &AdminClient, rest: &[&str]) -> Result<()> {
    let id = positional_arg(rest, 0, "id")?;
    let path = format!("/webhooks/{id}/rotate-secret/commit");
    let body = client.request(reqwest::Method::POST, &path, Some(json!({})))?;
    println!(
        "webhook {id} rotation committed (secret_fp={})",
        field(&body, "secret_fp"),
    );
    Ok(())
}

/// `webhook deliveries <id> [limit]` — a subscription's deliveries (the dead-letter
/// view), newest first: what is in flight and what was dropped after exhausting attempts.
fn webhook_deliveries(client: &AdminClient, rest: &[&str]) -> Result<()> {
    let id = positional_arg(rest, 0, "id")?;
    let limit: Option<i64> = rest
        .get(1)
        .map(|s| s.parse())
        .transpose()
        .context("limit must be an integer")?;
    let path = match limit {
        Some(n) => format!("/webhooks/{id}/deliveries?limit={n}"),
        None => format!("/webhooks/{id}/deliveries"),
    };
    let body = client.request(reqwest::Method::GET, &path, None)?;
    render_list(&body, "deliveries", |row| {
        println!(
            "{}  {}  {}  attempts={}/{}  next={}  last_status={}  last_error={}",
            field(row, "id"),
            field(row, "state"),
            field(row, "event_type"),
            field(row, "attempts"),
            field(row, "max_attempts"),
            field(row, "next_attempt_at"),
            field(row, "last_status"),
            field(row, "last_error"),
        );
    });
    Ok(())
}

/// `webhook delivery-retry <id> <delivery_id>` — redrive a failed (dead-lettered)
/// delivery back to pending for immediate re-attempt. A delivery that is not failed
/// is refused (422).
fn webhook_delivery_retry(client: &AdminClient, rest: &[&str]) -> Result<()> {
    let id = positional_arg(rest, 0, "id")?;
    let delivery_id = positional_arg(rest, 1, "delivery_id")?;
    let path = format!("/webhooks/{id}/deliveries/{delivery_id}/retry");
    let body = client.request(reqwest::Method::POST, &path, Some(json!({})))?;
    println!(
        "delivery {} -> {}",
        field(&body, "id"),
        field(&body, "state"),
    );
    Ok(())
}

/// Build the single-field PATCH body for `webhook update`. Each call changes exactly
/// one field; an absent field is left untouched server-side. A `label` value of `-`
/// clears the label (a JSON null the PATCH route reads as "clear").
fn webhook_patch_body(field_name: &str, value: &str) -> Result<Value> {
    Ok(match field_name {
        "status" => json!({ "status": value }),
        "events" => {
            let events: Vec<&str> = value.split(',').filter(|s| !s.is_empty()).collect();
            json!({ "enabled_events": events })
        }
        "url" => json!({ "url": value }),
        "label" => {
            let label = if value == "-" {
                Value::Null
            } else {
                json!(value)
            };
            json!({ "label": label })
        }
        other => bail!("webhook update field must be status|events|url|label, got {other}"),
    })
}

// ---------------------------------------------------------------------------
// Tokens.
// ---------------------------------------------------------------------------

fn token_mint(client: &AdminClient, rest: &[&str]) -> Result<()> {
    // `token mint operator` -> POST /operator/token; `token mint account <id> [scopes]`.
    let kind = positional_arg(rest, 0, "operator|account")?;
    match kind {
        "operator" => {
            let body = client.request(reqwest::Method::POST, "/operator/token", None)?;
            println!("operator token (shown once): {}", field(&body, "token"));
            println!("expires_at: {}", field(&body, "expires_at"));
        }
        "account" => {
            let account_id = positional_arg(rest, 1, "account_id")?;
            let scopes: Vec<&str> = rest
                .get(2)
                .map(|s| s.split(',').filter(|s| !s.is_empty()).collect())
                .unwrap_or_default();
            let path = format!("/accounts/{account_id}/token");
            let body = client.request(
                reqwest::Method::POST,
                &path,
                Some(json!({ "scopes": scopes })),
            )?;
            println!("account token (shown once): {}", field(&body, "token"));
            println!("expires_at: {}", field(&body, "expires_at"));
        }
        other => bail!("token mint kind must be operator or account, got {other}"),
    }
    Ok(())
}

/// `token list` — the operator's access-token roster (ids and lifecycle only;
/// secrets are unrecoverable by design).
fn token_list(client: &AdminClient) -> Result<()> {
    let body = client.request(reqwest::Method::GET, "/tokens", None)?;
    render_list(&body, "tokens", |row| {
        println!(
            "{}  account_id={}  scopes={}  expires_at={}  revoked_at={}",
            field(row, "token_id"),
            field(row, "account_id"),
            field(row, "scopes"),
            field(row, "expires_at"),
            field(row, "revoked_at"),
        );
    });
    Ok(())
}

/// `token revoke <token_id>` — revoke one access token: the targeted kill switch
/// for a single leaked token without a full root rotation. Tokens minted under
/// the revoked one die with it (the mint lineage).
fn token_revoke(client: &AdminClient, rest: &[&str]) -> Result<()> {
    let token_id = positional_arg(rest, 0, "token_id")?;
    let path = format!("/tokens/{token_id}/revoke");
    let body = client.request(reqwest::Method::POST, &path, Some(json!({})))?;
    println!("token {} revoked={}", token_id, field(&body, "revoked"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Audit.
// ---------------------------------------------------------------------------

fn audit_tail(client: &AdminClient, rest: &[&str]) -> Result<()> {
    let limit = rest
        .first()
        .map(|s| s.parse::<i64>())
        .transpose()
        .context("limit must be an integer")?
        .unwrap_or(20);
    let path = format!("/audit?limit={limit}");
    let body = client.request(reqwest::Method::GET, &path, None)?;
    render_list(&body, "audit entries", |row| {
        println!(
            "{}  {}  {} {}  by {}",
            field(row, "occurred_at"),
            field(row, "action"),
            field(row, "target_type"),
            field(row, "target_id"),
            field(row, "actor_kind"),
        );
    });
    Ok(())
}

// ---------------------------------------------------------------------------
// Rendering helpers.
// ---------------------------------------------------------------------------

/// The `data` array of a list envelope, or an empty slice.
fn list_rows(body: &Value) -> Vec<&Value> {
    body.get("data")
        .and_then(|d| d.as_array())
        .map(|a| a.iter().collect())
        .unwrap_or_default()
}

/// Render a list envelope: each row through `render`, or a one-line `no <things>`
/// notice to stdout when the list is empty.
///
/// Every list command routes through this, so an empty result is never a silent
/// blank: an operator can tell "nothing here" apart from a command that produced no
/// output at all (or one whose output scrolled off), without second-guessing
/// whether the call even ran.
fn render_list(body: &Value, empty_label: &str, mut render: impl FnMut(&Value)) {
    let rows = list_rows(body);
    if rows.is_empty() {
        println!("no {empty_label}");
        return;
    }
    for row in rows {
        render(row);
    }
}

/// Render a JSON field as a compact display string. An object/array renders as its
/// compact JSON; a string drops its quotes; a null renders as `-`.
fn field(value: &Value, key: &str) -> String {
    match value.get(key) {
        None | Some(Value::Null) => "-".to_string(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    }
}

/// A required positional argument at `index`, or an error naming what is missing.
fn positional_arg<'a>(rest: &[&'a str], index: usize, name: &str) -> Result<&'a str> {
    rest.get(index)
        .copied()
        .ok_or_else(|| anyhow!("missing required argument: {name}"))
}

/// Print the admin command usage to stderr.
fn print_usage() {
    eprintln!("usage: gateway admin <group> <action> [args] [--url URL] [--token-stdin]");
    eprintln!("  account create");
    eprintln!("  account list");
    eprintln!("  account disable <account_id>");
    eprintln!("  account enable <account_id>");
    eprintln!("  account fund <account_id> <amount_usd_micros> <reason>");
    eprintln!("  account clamp-debit <account_id> <amount_usd_micros> <reason> <ref>");
    eprintln!("  account usage <account_id>");
    eprintln!("  account margin set <account_id> <margin_pct>");
    eprintln!("  account margin unset <account_id>");
    eprintln!("  key create <account_id> <scopes,csv> [rate_limit_per_min]");
    eprintln!("  key list <account_id>");
    eprintln!("  key revoke <account_id> <key_id>");
    eprintln!("  key relabel <account_id> <key_id> [label]");
    eprintln!("  credential rotate-root [label]");
    eprintln!("  credential list");
    eprintln!("  credential revoke <credential_id>");
    eprintln!("  wallet list");
    eprintln!("  wallet operator-balance");
    eprintln!("  wallet drain <wallet_id>");
    eprintln!("  wallet reactivate <wallet_id>");
    eprintln!("  wallet register <label> <address> <network> [scope] [scope_account_id]");
    eprintln!("  wallet grant <wallet_id> <service|operator|account> [account_id]");
    eprintln!("  wallet grant-revoke <wallet_id> <grant_id>");
    eprintln!("  storage source register <label> <backend> <address> [scope] [scope_account_id]");
    eprintln!("  storage source grant <source_id> <service|operator|account> [account_id]");
    eprintln!("  storage source grant-revoke <source_id> <grant_id>");
    eprintln!("  storage source drain <source_id>");
    eprintln!("  storage sources");
    eprintln!("  storage top-up <ar_amount_winston> <idempotency_key> [funding_source_id]");
    eprintln!("  storage top-up-register <topup_id>");
    eprintln!("  storage top-ups");
    eprintln!("  storage funding");
    eprintln!("  storage operator-balance");
    eprintln!("  chain provider-usage [days]");
    eprintln!("  pricing fx");
    eprintln!("  webhook health");
    eprintln!("  webhook create <url> [events,csv] [label]");
    eprintln!("  webhook list");
    eprintln!("  webhook get <id>");
    eprintln!("  webhook update <id> <status|events|url|label> <value>");
    eprintln!("  webhook delete <id>");
    eprintln!("  webhook rotate-secret <id>");
    eprintln!("  webhook rotate-secret-commit <id>");
    eprintln!("  webhook deliveries <id> [limit]");
    eprintln!("  webhook delivery-retry <id> <delivery_id>");
    eprintln!("  token mint operator");
    eprintln!("  token mint account <account_id> [scopes,csv]");
    eprintln!("  token list");
    eprintln!("  token revoke <token_id>");
    eprintln!("  audit tail [limit]");
    eprintln!();
    eprintln!("credential: the bearer is sourced as {CONTROL_TOKEN_ENV} (recommended), then");
    eprintln!("      --token-stdin (read from a pipe). Both keep the credential off argv,");
    eprintln!("      so it never leaks into shell history or process listings (`ps aux`);");
    eprintln!("      an argv --token flag no longer exists. `wallet register`, `storage");
    eprintln!("      source register`, `credential rotate-root`, and `credential revoke`");
    eprintln!("      require the high-authority operator root credential.");
    eprintln!();
    eprintln!("storage top-up: the idempotency key is REQUIRED — the conversion is an");
    eprintln!("      irreversible fund movement, so a retry with the SAME key replays the");
    eprintln!("      journalled conversion instead of signing a second transfer. Use a");
    eprintln!("      fresh key (e.g. a UUID) for each new top-up.");
    eprintln!();
    eprintln!("base url: the control-plane base is sourced as --url, then {CONTROL_URL_ENV},");
    eprintln!("      then the default {DEFAULT_CONTROL_URL}. It is the FULL base INCLUDING the");
    eprintln!("      version segment (e.g. https://gateway.example.com/control/v1); each command");
    eprintln!("      appends only its bare resource suffix.");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_flags_separates_flags_from_positionals() {
        let args = vec![
            "account".to_string(),
            "create".to_string(),
            "--url".to_string(),
            "http://x".to_string(),
        ];
        let (positional, flags) = split_flags(&args).expect("split");
        assert_eq!(positional, vec!["account", "create"]);
        assert_eq!(flags.url.as_deref(), Some("http://x"));
        assert!(flags.token_stdin.is_none());
    }

    #[test]
    fn the_removed_argv_token_flag_is_rejected_with_migration_guidance() {
        // `--token` put the bearer on argv (visible in `ps` and shell history);
        // it is refused outright, and the error names both leak-free sources so
        // an operator with an old script knows exactly what to change.
        let args = vec![
            "account".to_string(),
            "list".to_string(),
            "--token".to_string(),
            "t".to_string(),
        ];
        // Match rather than `expect_err`: the Ok arm carries `Flags`, which
        // deliberately has no `Debug` (its stdin token would render).
        let err = match split_flags(&args) {
            Ok(_) => panic!("--token must be refused"),
            Err(e) => e,
        };
        let msg = err.to_string();
        assert!(msg.contains(CONTROL_TOKEN_ENV), "names the env var: {msg}");
        assert!(msg.contains("--token-stdin"), "names the stdin pipe: {msg}");
    }

    #[test]
    fn a_bearer_token_debug_render_is_redacted() {
        let token = BearerToken(Zeroizing::new("ctl_super-secret".to_string()));
        let rendered = format!("{token:?}");
        assert!(
            !rendered.contains("super-secret"),
            "the debug render must not leak the secret, got {rendered}"
        );
    }

    #[test]
    fn field_renders_strings_nulls_and_scalars() {
        let v = json!({ "s": "abc", "n": 7, "z": null });
        assert_eq!(field(&v, "s"), "abc");
        assert_eq!(field(&v, "n"), "7");
        assert_eq!(field(&v, "z"), "-");
        assert_eq!(field(&v, "missing"), "-");
    }

    #[test]
    fn positional_arg_reports_a_missing_argument() {
        let rest = ["a"];
        assert_eq!(positional_arg(&rest, 0, "first").unwrap(), "a");
        assert!(positional_arg(&rest, 1, "second").is_err());
    }

    #[test]
    fn grant_body_carries_the_scope_for_a_non_account_scope() {
        // rest[0] is the resource id (wallet/source); rest[1] is the scope.
        let rest = ["wallet-id", "service"];
        let body = grant_body(&rest).expect("a service grant needs no account id");
        assert_eq!(body["scope"], json!("service"));
        assert!(
            body.get("account_id").is_none(),
            "a non-account scope must not carry an account_id"
        );

        let rest = ["wallet-id", "operator"];
        let body = grant_body(&rest).expect("an operator grant needs no account id");
        assert_eq!(body["scope"], json!("operator"));
        assert!(body.get("account_id").is_none());
    }

    #[test]
    fn grant_body_requires_and_carries_the_account_id_for_an_account_scope() {
        let rest = ["wallet-id", "account", "acc-123"];
        let body = grant_body(&rest).expect("an account grant with an id parses");
        assert_eq!(body["scope"], json!("account"));
        assert_eq!(body["account_id"], json!("acc-123"));

        // An account scope without the account id is a parse error, not a body that
        // silently drops the id and lets the server reject it less clearly.
        let rest = ["wallet-id", "account"];
        assert!(
            grant_body(&rest).is_err(),
            "an account scope must require the account id locally"
        );
    }

    #[test]
    fn webhook_patch_body_maps_each_field_to_its_wire_shape() {
        assert_eq!(
            webhook_patch_body("status", "paused").unwrap(),
            json!({ "status": "paused" })
        );
        assert_eq!(
            webhook_patch_body("url", "https://example/hook").unwrap(),
            json!({ "url": "https://example/hook" })
        );
        // A CSV becomes the event-filter array; an empty CSV means "all events".
        assert_eq!(
            webhook_patch_body("events", "poe.published,poe.refunded").unwrap(),
            json!({ "enabled_events": ["poe.published", "poe.refunded"] })
        );
        assert_eq!(
            webhook_patch_body("events", "").unwrap(),
            json!({ "enabled_events": [] })
        );
    }

    #[test]
    fn webhook_patch_body_clears_the_label_on_a_bare_dash() {
        // A `-` clears the label (a JSON null the PATCH route reads as "clear"); any
        // other value sets it. The two must not collapse to the same body.
        assert_eq!(
            webhook_patch_body("label", "-").unwrap(),
            json!({ "label": null })
        );
        assert_eq!(
            webhook_patch_body("label", "prod").unwrap(),
            json!({ "label": "prod" })
        );
    }

    #[test]
    fn webhook_patch_body_rejects_an_unknown_field() {
        assert!(
            webhook_patch_body("secret", "x").is_err(),
            "only the patchable fields are accepted; an unknown field is a local error"
        );
    }
}
