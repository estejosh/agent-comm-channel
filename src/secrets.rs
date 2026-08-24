//! Secrets manager for the agent-comm-channel client.
//!
//! Two tiers, deliberately separated so that a compromised/unattended agent can
//! reach only the low-value tier:
//!
//! 1. **Git tier** — `age`-encrypted secrets stored in the `pc-secrets` repo,
//!    encrypted to every enrolled PC's public key. The agent has this PC's key,
//!    so it can `get`/`set`/`list` freely; the repo only ever holds ciphertext,
//!    and it auto-syncs to every PC. Durable + shareable, modest blast radius.
//!
//! 2. **Local vault** — an append-only, passphrase-encrypted store at
//!    `X:\secrets-vault` (configurable). Encryption at rest is a passphrase-
//!    derived key (Argon2id -> XChaCha20-Poly1305). *Access* is gated by TOTP
//!    (RFC 6238, i.e. Google Authenticator) plus 10 one-time backup codes. The
//!    human must be present (passphrase + 6-digit code) for every open, unless a
//!    short timed lease is active. Nothing here is ever overwritten or deleted:
//!    every `set` appends a new timestamped version, so a secret cannot be lost.
//!
//! TOTP is authentication, not encryption — so the TOTP secret and backup-code
//! hashes live *inside* the passphrase-encrypted envelope. Opening the vault
//! therefore requires the passphrase AND a live code: two real factors.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use argon2::Argon2;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

type HmacSha1 = Hmac<sha1::Sha1>;

// The vault lives OUTSIDE the git checkout so re-cloning/corrupting the repo
// cannot take the canonical store with it. Overridable via CHANNEL_VAULT_DIR.
pub fn vault_dir() -> PathBuf {
    if let Ok(p) = std::env::var("CHANNEL_VAULT_DIR") {
        return PathBuf::from(p);
    }
    // Default: X:\secrets-vault on Windows, ~/secrets-vault elsewhere.
    #[cfg(windows)]
    {
        PathBuf::from(r"X:\secrets-vault")
    }
    #[cfg(not(windows))]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        PathBuf::from(home).join("secrets-vault")
    }
}

fn meta_path(dir: &Path) -> PathBuf {
    dir.join("vault.meta")
}
fn lease_path(dir: &Path) -> PathBuf {
    dir.join(".lease")
}
fn secret_dir(dir: &Path, name: &str) -> PathBuf {
    dir.join("secrets").join(slug(name))
}

fn slug(s: &str) -> String {
    let out: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '-'
            }
        })
        .collect();
    if out.is_empty() {
        "unnamed".into()
    } else {
        out
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn subsec_nanos() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0)
}

/// Version filenames must be unique per second: `vault set` twice in the same
/// second used to collide on one filename and silently drop a version. The
/// zero-padded nanos suffix keeps every version the same width, so the
/// lexicographically-last file is still the latest one.
fn version_file_name() -> String {
    format!("{}.{:09}", iso_stamp(), subsec_nanos())
}

fn iso_stamp() -> String {
    // Reuse the same civil-time conversion as main via a small inline copy.
    let secs = now_secs() as i64;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{h:02}-{mi:02}-{s:02}Z")
}

// ------------------------------------------------------------------ crypto core
/// Derive a 32-byte key from a passphrase with Argon2id and the given salt.
fn derive_key(passphrase: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .expect("argon2 kdf");
    key
}

/// Encrypt `plaintext` with a fresh random nonce. Layout: [24-byte nonce || ct].
fn seal(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .expect("aead encrypt");
    let mut out = Vec::with_capacity(24 + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

fn open(key: &[u8; 32], blob: &[u8]) -> Option<Vec<u8>> {
    if blob.len() < 24 {
        return None;
    }
    let (nonce, ct) = blob.split_at(24);
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher.decrypt(XNonce::from_slice(nonce), ct).ok()
}

// ------------------------------------------------------------------------ TOTP
/// RFC 6238 TOTP, 6 digits, 30-second step, SHA-1 (Google Authenticator default).
/// Takes the clock as a parameter so the RFC test vectors are unit-testable;
/// `totp_now` is the wall-clock wrapper.
fn totp_at(secret: &[u8], unix_secs: u64, skew_step: i64) -> String {
    let counter = ((unix_secs as i64 / 30) + skew_step) as u64;
    let mut mac = <HmacSha1 as Mac>::new_from_slice(secret).expect("hmac key");
    mac.update(&counter.to_be_bytes());
    let hs = mac.finalize().into_bytes();
    let offset = (hs[hs.len() - 1] & 0x0f) as usize;
    let bin = ((hs[offset] as u32 & 0x7f) << 24)
        | ((hs[offset + 1] as u32) << 16)
        | ((hs[offset + 2] as u32) << 8)
        | (hs[offset + 3] as u32);
    format!("{:06}", bin % 1_000_000)
}

fn totp_now(secret: &[u8], skew_step: i64) -> String {
    totp_at(secret, now_secs(), skew_step)
}

/// Accept a code if it matches the current step or the immediately adjacent
/// steps (tolerates ~30s clock skew and typing lag).
fn totp_verify(secret: &[u8], code: &str) -> bool {
    let code = code.trim();
    (-1..=1).any(|skew| totp_now(secret, skew) == code)
}

fn otpauth_uri(secret_b32: &str, label: &str) -> String {
    format!(
        "otpauth://totp/{label}?secret={secret_b32}&issuer=pc-secrets&algorithm=SHA1&digits=6&period=30"
    )
}

// --------------------------------------------------------------- vault metadata
// vault.meta on disk = [16-byte salt || sealed(meta_json)]. The salt is public;
// everything sensitive (TOTP secret, backup-code hashes) is inside the sealed
// blob, so the passphrase is required even to *check* a TOTP code.
struct VaultMeta {
    totp_secret: Vec<u8>,
    backup_hashes: Vec<String>, // sha256 hex of unused one-time codes
}

fn parse_meta_json(s: &str) -> VaultMeta {
    // Tiny hand parser (no serde dep): fields are on their own lines.
    let mut totp_b32 = String::new();
    let mut backups = Vec::new();
    for line in s.lines() {
        if let Some(v) = line.strip_prefix("totp:") {
            totp_b32 = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("backup:") {
            let v = v.trim();
            if !v.is_empty() {
                backups.push(v.to_string());
            }
        }
    }
    VaultMeta {
        totp_secret: BASE32_NOPAD.decode(totp_b32.as_bytes()).unwrap_or_default(),
        backup_hashes: backups,
    }
}

fn meta_to_json(m: &VaultMeta) -> String {
    let mut s = format!("totp: {}\n", BASE32_NOPAD.encode(&m.totp_secret));
    for b in &m.backup_hashes {
        s.push_str(&format!("backup: {b}\n"));
    }
    s
}

fn sha256_hex(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn read_meta(dir: &Path, key: &[u8; 32]) -> Option<VaultMeta> {
    let raw = fs::read(meta_path(dir)).ok()?;
    if raw.len() < 16 {
        return None;
    }
    let sealed = &raw[16..];
    let plain = open(key, sealed)?;
    Some(parse_meta_json(&String::from_utf8_lossy(&plain)))
}

fn read_salt(dir: &Path) -> Option<[u8; 16]> {
    let raw = fs::read(meta_path(dir)).ok()?;
    if raw.len() < 16 {
        return None;
    }
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&raw[..16]);
    Some(salt)
}

fn write_meta(dir: &Path, salt: &[u8; 16], key: &[u8; 32], m: &VaultMeta) {
    let sealed = seal(key, meta_to_json(m).as_bytes());
    let mut out = Vec::with_capacity(16 + sealed.len());
    out.extend_from_slice(salt);
    out.extend_from_slice(&sealed);
    let _ = fs::create_dir_all(dir);
    let _ = fs::write(meta_path(dir), out);
}

// ------------------------------------------------------------------ user input
fn prompt_passphrase(confirm: bool) -> String {
    // Test/automation seam: CHANNEL_VAULT_PASSPHRASE bypasses the TTY prompt.
    // Intended for CI and the reference test-harness only — using it in normal
    // operation defeats the "human must be present" guarantee, so it warns.
    if let Ok(p) = std::env::var("CHANNEL_VAULT_PASSPHRASE") {
        eprintln!("[warn] passphrase taken from CHANNEL_VAULT_PASSPHRASE (non-interactive mode)");
        return p;
    }
    let p = rpassword::prompt_password("vault passphrase: ").unwrap_or_default();
    if confirm {
        let p2 = rpassword::prompt_password("confirm passphrase: ").unwrap_or_default();
        if p != p2 {
            eprintln!("passphrases do not match");
            std::process::exit(1);
        }
    }
    p
}

fn prompt_line(label: &str) -> String {
    use std::io::Write;
    // Prompt on stderr so stdout stays clean — `vault get` writes only the secret
    // value to stdout, so a script can capture it without the prompt leaking in.
    eprint!("{label}");
    let _ = std::io::stderr().flush();
    let mut s = String::new();
    let _ = std::io::stdin().read_line(&mut s);
    s.trim().to_string()
}

// ---------------------------------------------------------------------- leases
// A lease lets the auto-pull agent batch vault reads hands-off after ONE human
// unlock. On disk: sealed(expiry_secs) under the vault key, so a lease file is
// worthless without the passphrase. Absent/expired -> every access needs 2FA.
fn write_lease(dir: &Path, key: &[u8; 32], ttl_secs: u64) {
    let expiry = now_secs() + ttl_secs;
    let sealed = seal(key, expiry.to_string().as_bytes());
    let _ = fs::write(lease_path(dir), sealed);
}

fn lease_active(dir: &Path, key: &[u8; 32]) -> bool {
    let Ok(raw) = fs::read(lease_path(dir)) else {
        return false;
    };
    let Some(plain) = open(key, &raw) else {
        return false;
    };
    let Ok(expiry) = String::from_utf8_lossy(&plain).parse::<u64>() else {
        return false;
    };
    expiry > now_secs()
}

/// Verify the second factor: a live TOTP code OR a one-time backup code (which is
/// then consumed by rewriting meta without it). Returns true on success.
fn verify_second_factor(dir: &Path, salt: &[u8; 16], key: &[u8; 32], mut meta: VaultMeta) -> bool {
    let code = prompt_line("2FA code (6-digit authenticator, or a backup code): ");
    if totp_verify(&meta.totp_secret, &code) {
        return true;
    }
    // Backup code path: match by hash, then consume it.
    let h = sha256_hex(&code);
    if let Some(pos) = meta.backup_hashes.iter().position(|x| *x == h) {
        meta.backup_hashes.remove(pos);
        write_meta(dir, salt, key, &meta);
        eprintln!(
            "(backup code accepted and consumed; {} left)",
            meta.backup_hashes.len()
        );
        return true;
    }
    false
}

/// Full gate: passphrase -> derive key -> read meta -> require live lease OR a
/// passed second factor. Returns the vault key on success.
fn unlock(dir: &Path, allow_lease: bool) -> Option<[u8; 32]> {
    let salt = read_salt(dir).or_else(|| {
        eprintln!("no vault here — run `channel vault init` first");
        None
    })?;
    let mut pass = prompt_passphrase(false);
    let key = derive_key(&pass, &salt);
    pass.zeroize();

    let meta = match read_meta(dir, &key) {
        Some(m) => m,
        None => {
            eprintln!("wrong passphrase (could not decrypt vault metadata)");
            return None;
        }
    };
    if allow_lease && lease_active(dir, &key) {
        return Some(key);
    }
    if verify_second_factor(dir, &salt, &key, meta) {
        Some(key)
    } else {
        eprintln!("2FA failed");
        None
    }
}

// ----------------------------------------------------------------------- public
pub fn vault_init() {
    let dir = vault_dir();
    if meta_path(&dir).exists() {
        eprintln!("vault already initialized at {}", dir.display());
        eprintln!("(refusing to overwrite — that would orphan existing secrets)");
        std::process::exit(1);
    }
    println!("Initializing encrypted vault at {}", dir.display());
    let mut pass = prompt_passphrase(true);
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    let key = derive_key(&pass, &salt);
    pass.zeroize();

    // Fresh 20-byte TOTP secret.
    let mut totp_secret = vec![0u8; 20];
    rand::thread_rng().fill_bytes(&mut totp_secret);

    // 10 one-time backup codes (store only their hashes).
    let mut plaintext_codes = Vec::new();
    let mut backup_hashes = Vec::new();
    for _ in 0..10 {
        let mut b = [0u8; 5];
        rand::thread_rng().fill_bytes(&mut b);
        let code = format!(
            "{}-{}",
            BASE32_NOPAD.encode(&b[..3])[..4].to_lowercase(),
            BASE32_NOPAD.encode(&b[2..])[..4].to_lowercase()
        );
        backup_hashes.push(sha256_hex(&code));
        plaintext_codes.push(code);
    }

    let meta = VaultMeta {
        totp_secret: totp_secret.clone(),
        backup_hashes,
    };
    write_meta(&dir, &salt, &key, &meta);
    let _ = fs::create_dir_all(dir.join("secrets"));

    let b32 = BASE32_NOPAD.encode(&totp_secret);
    println!("\n=== SCAN THIS INTO GOOGLE AUTHENTICATOR (or any TOTP app) ===");
    println!("  Manual key : {b32}");
    println!("  otpauth URI: {}", otpauth_uri(&b32, "pc-secrets:vault"));
    println!("\n=== 10 ONE-TIME BACKUP CODES — store offline, each works once ===");
    for c in &plaintext_codes {
        println!("  {c}");
    }
    println!("\nVault ready. `vault set`/`vault get` now require passphrase + a 2FA code.");
    totp_secret.zeroize();
}

pub fn vault_set(name: &str, value: Option<String>) {
    let dir = vault_dir();
    let Some(key) = unlock(&dir, /*allow_lease=*/ true) else {
        std::process::exit(1)
    };
    let value = value.unwrap_or_else(|| {
        use std::io::Read;
        let mut s = String::new();
        let _ = std::io::stdin().read_to_string(&mut s);
        s.trim_end().to_string()
    });
    // Append-only: a NEW timestamped version file; never overwrite/delete.
    let sdir = secret_dir(&dir, name);
    let _ = fs::create_dir_all(&sdir);
    let blob = seal(&key, value.as_bytes());
    let file = sdir.join(format!("{}.bin", version_file_name()));
    if fs::write(&file, blob).is_err() {
        eprintln!("failed to write secret version");
        std::process::exit(1);
    }
    println!(
        "stored '{}' (version {})",
        slug(name),
        file.file_name().unwrap().to_string_lossy()
    );
}

pub fn vault_get(name: &str) {
    let dir = vault_dir();
    let Some(key) = unlock(&dir, true) else {
        std::process::exit(1)
    };
    let sdir = secret_dir(&dir, name);
    // Latest version = lexicographically-last timestamped file.
    let latest = fs::read_dir(&sdir).ok().and_then(|rd| {
        rd.filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("bin"))
            .max_by(|a, b| a.file_name().cmp(&b.file_name()))
    });
    match latest {
        Some(p) => match fs::read(&p).ok().and_then(|b| open(&key, &b)) {
            Some(plain) => println!("{}", String::from_utf8_lossy(&plain)),
            None => {
                eprintln!("failed to decrypt '{}'", slug(name));
                std::process::exit(1);
            }
        },
        None => {
            eprintln!("no secret named '{}'", slug(name));
            std::process::exit(1);
        }
    }
}

pub fn vault_list() {
    let dir = vault_dir();
    // Listing names does not reveal values; still require the gate so mere
    // presence of the vault contents is not leaked to an unattended agent.
    let Some(_key) = unlock(&dir, true) else {
        std::process::exit(1)
    };
    let sroot = dir.join("secrets");
    let Ok(rd) = fs::read_dir(&sroot) else {
        println!("(vault empty)");
        return;
    };
    let mut any = false;
    for e in rd.filter_map(|e| e.ok()) {
        if e.path().is_dir() {
            let versions = fs::read_dir(e.path()).map(|r| r.count()).unwrap_or(0);
            println!(
                "{}  ({versions} version{})",
                e.file_name().to_string_lossy(),
                if versions == 1 { "" } else { "s" }
            );
            any = true;
        }
    }
    if !any {
        println!("(vault empty)");
    }
}

pub fn vault_unlock(ttl_mins: u64) {
    let dir = vault_dir();
    // Force full 2FA (no lease shortcut) to START a lease.
    let Some(key) = unlock(&dir, /*allow_lease=*/ false) else {
        std::process::exit(1)
    };
    write_lease(&dir, &key, ttl_mins * 60);
    println!("vault unlocked for {ttl_mins} min — agent may read the vault hands-off until then");
}

pub fn vault_lock() {
    let dir = vault_dir();
    let _ = fs::remove_file(lease_path(&dir));
    println!("vault re-locked (lease cleared)");
}

// ============================================================================
//  GIT TIER  —  age-encrypted, multi-recipient, agent-accessible, auto-synced
// ============================================================================
//
// Layout inside the pc-secrets repo (whatever dir the binary runs in):
//   keys.txt          committed — one age *public* recipient per line, prefixed
//                     "<node-id> age1..."  (who secrets are encrypted TO)
//   secrets/<name>.age committed — armored ciphertext, encrypted to everyone in
//                     keys.txt
//   .identity         GITIGNORED — this PC's age *private* key (never committed)
//
// The agent can freely read/write here: the repo only ever holds ciphertext it
// cannot expand beyond what this PC's key already decrypts. That is the whole
// point of keeping the low-value tier separate from the human-gated vault.

use std::io::{Read, Write};

fn git_root() -> PathBuf {
    std::env::current_dir().expect("cwd")
}

fn identity_path(root: &Path) -> PathBuf {
    root.join(".identity")
}
fn keys_path(root: &Path) -> PathBuf {
    root.join("keys.txt")
}
fn git_secret_path(root: &Path, name: &str) -> PathBuf {
    root.join("secrets").join(format!("{}.age", slug(name)))
}

/// Create this PC's age keypair if absent, then make sure keys.txt maps the
/// node id to THIS PC's current public key. The keys.txt entry is derived from
/// the local `.identity` (the authoritative private half), so a re-enroll after
/// a lost/regenerated identity repairs a stale line instead of leaving other
/// PCs encrypting to a key this one can no longer open.
pub fn secret_enroll(node: &str) {
    let root = git_root();
    let id_path = identity_path(&root);
    if !id_path.exists() {
        let id = age::x25519::Identity::generate();
        let secret = id.to_string(); // "AGE-SECRET-KEY-1..."
                                     // Store the private identity locally, gitignored.
        use age::secrecy::ExposeSecret;
        if fs::write(&id_path, format!("{}\n", secret.expose_secret())).is_err() {
            eprintln!("failed to write .identity");
            std::process::exit(1);
        }
        println!("generated identity -> {} (gitignored)", id_path.display());
    } else {
        eprintln!("this PC already has an identity at {}", id_path.display());
    }

    // Recover the identity (freshly created or pre-existing) and upsert its
    // public key under this node id.
    let id_text = fs::read_to_string(&id_path).unwrap_or_else(|_| {
        eprintln!("failed to read {}", id_path.display());
        std::process::exit(1);
    });
    let identity: age::x25519::Identity = id_text
        .lines()
        .find(|l| l.starts_with("AGE-SECRET-KEY-"))
        .unwrap_or("")
        .parse()
        .unwrap_or_else(|_| {
            eprintln!("malformed .identity — delete it and re-run `channel secret enroll`");
            std::process::exit(1);
        });
    let pubkey = identity.to_public().to_string();
    let node = slug(node);

    let existing = fs::read_to_string(keys_path(&root)).unwrap_or_default();
    let mut changed = false;
    let mut lines: Vec<String> = Vec::new();
    for line in existing.lines() {
        if line.split_whitespace().next() == Some(node.as_str()) {
            match line.split_whitespace().nth(1) {
                Some(key) if key == pubkey => lines.push(line.to_string()),
                _ => {
                    eprintln!(
                        "keys.txt had a different key for '{node}' — replacing with this PC's"
                    );
                    lines.push(format!("{node} {pubkey}"));
                    changed = true;
                }
            }
        } else {
            lines.push(line.to_string());
        }
    }
    if !existing
        .lines()
        .any(|l| l.split_whitespace().next() == Some(node.as_str()))
    {
        lines.push(format!("{node} {pubkey}"));
        changed = true;
    }
    if changed {
        let mut out = String::new();
        for l in &lines {
            out.push_str(l);
            out.push('\n');
        }
        if fs::write(keys_path(&root), out).is_err() {
            eprintln!("failed to write keys.txt");
            std::process::exit(1);
        }
        println!("added/updated '{node}' in keys.txt");
    } else {
        println!("'{}' already in keys.txt — leaving it", node);
    }
    println!("commit keys.txt and push so other PCs can encrypt to this one.");
}

fn load_recipients(root: &Path) -> Vec<age::x25519::Recipient> {
    let text = fs::read_to_string(keys_path(root)).unwrap_or_else(|_| {
        eprintln!("no keys.txt — run `channel secret enroll --node <id>` first");
        std::process::exit(1);
    });
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // format: "<node> age1..."  — take the last whitespace field as the key
        if let Some(key) = line.split_whitespace().last() {
            match key.parse::<age::x25519::Recipient>() {
                Ok(r) => out.push(r),
                Err(_) => eprintln!("[warn] skipping malformed recipient: {line}"),
            }
        }
    }
    if out.is_empty() {
        eprintln!("keys.txt has no valid recipients");
        std::process::exit(1);
    }
    out
}

pub fn secret_set(name: &str, value: Option<String>) {
    let root = git_root();
    let recipients = load_recipients(&root);
    let value = value.unwrap_or_else(|| {
        let mut s = String::new();
        let _ = std::io::stdin().read_to_string(&mut s);
        s.trim_end().to_string()
    });

    let recips: Vec<&dyn age::Recipient> = recipients
        .iter()
        .map(|r| r as &dyn age::Recipient)
        .collect();
    let encryptor =
        age::Encryptor::with_recipients(recips.into_iter()).expect("at least one recipient");

    let mut armored = vec![];
    {
        let armor_writer =
            age::armor::ArmoredWriter::wrap_output(&mut armored, age::armor::Format::AsciiArmor)
                .expect("armor writer");
        let mut w = encryptor.wrap_output(armor_writer).expect("wrap output");
        w.write_all(value.as_bytes()).expect("write plaintext");
        let armor_writer = w.finish().expect("finish stream");
        armor_writer.finish().expect("finish armor");
    }

    let path = git_secret_path(&root, name);
    let _ = fs::create_dir_all(path.parent().unwrap());
    if fs::write(&path, &armored).is_err() {
        eprintln!("failed to write encrypted secret");
        std::process::exit(1);
    }
    println!(
        "encrypted '{}' to {} recipient(s) -> {}",
        slug(name),
        recipients.len(),
        path.display()
    );
    println!("commit & push (or let `channel` do it) to sync to other PCs.");
}

pub fn secret_get(name: &str) {
    let root = git_root();
    let id_text = fs::read_to_string(identity_path(&root)).unwrap_or_else(|_| {
        eprintln!("no .identity here — run `channel secret enroll --node <id>` first");
        std::process::exit(1);
    });
    let identity: age::x25519::Identity = id_text
        .lines()
        .find(|l| l.starts_with("AGE-SECRET-KEY-"))
        .unwrap_or("")
        .parse()
        .unwrap_or_else(|_| {
            eprintln!("malformed .identity");
            std::process::exit(1);
        });

    let path = git_secret_path(&root, name);
    let ct = fs::read(&path).unwrap_or_else(|_| {
        eprintln!("no secret named '{}'", slug(name));
        std::process::exit(1);
    });

    let armor_reader = age::armor::ArmoredReader::new(&ct[..]);
    let decryptor = match age::Decryptor::new(armor_reader) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("failed to read age file: {e}");
            std::process::exit(1);
        }
    };
    let mut reader = match decryptor.decrypt(std::iter::once(&identity as &dyn age::Identity)) {
        Ok(r) => r,
        Err(_) => {
            eprintln!(
                "this PC's key cannot decrypt '{}' (not a recipient?)",
                slug(name)
            );
            std::process::exit(1);
        }
    };
    let mut out = Vec::new();
    if reader.read_to_end(&mut out).is_err() {
        eprintln!("decryption stream error");
        std::process::exit(1);
    }
    // secret value only, to stdout
    print!("{}", String::from_utf8_lossy(&out));
}

pub fn secret_list() {
    let root = git_root();
    let sroot = root.join("secrets");
    let Ok(rd) = fs::read_dir(&sroot) else {
        println!("(no secrets yet)");
        return;
    };
    let mut any = false;
    for e in rd.filter_map(|e| e.ok()) {
        let p = e.path();
        if p.extension().and_then(|s| s.to_str()) == Some("age") {
            if let Some(stem) = p.file_stem().and_then(|s| s.to_str()) {
                println!("{stem}");
                any = true;
            }
        }
    }
    if !any {
        println!("(no secrets yet)");
    }
}

// ------------------------------------------------------------------------
//  Tests — pure logic only; nothing here touches a real vault directory.
// ------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    // --- AEAD core ---------------------------------------------------------
    #[test]
    fn seal_open_roundtrip() {
        let key = [7u8; 32];
        let blob = seal(&key, b"attack at dawn");
        assert_eq!(
            open(&key, &blob).as_deref(),
            Some(b"attack at dawn".as_slice())
        );
    }

    #[test]
    fn open_rejects_tampered_and_short_blobs() {
        let key = [9u8; 32];
        let mut blob = seal(&key, b"secret");
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert_eq!(open(&key, &blob), None);
        assert_eq!(open(&key, &blob[..10]), None);
    }

    #[test]
    fn fresh_nonce_changes_ciphertext() {
        let key = [3u8; 32];
        assert_ne!(seal(&key, b"x"), seal(&key, b"x"));
    }

    // --- TOTP: RFC 6238 SHA-1 test vectors (6-digit truncation) ------------
    #[test]
    fn totp_matches_rfc6238_vectors() {
        let secret = b"12345678901234567890";
        // (unix time, expected 6-digit code)
        let cases = [
            (59u64, "287082"),
            (1_111_111_109, "081804"),
            (1_111_111_111, "050471"),
            (1_234_567_890, "005924"),
            (2_000_000_000, "279037"),
            (20_000_000_000, "353130"),
        ];
        for (t, want) in cases {
            assert_eq!(totp_at(secret, t, 0), want, "vector at t={t}");
        }
    }

    #[test]
    fn totp_skew_steps_shift_window() {
        let secret = b"12345678901234567890";
        let t = 59u64;
        assert_eq!(totp_at(secret, t + 30, -1), totp_at(secret, t, 0));
        assert_ne!(totp_at(secret, t + 30, 0), totp_at(secret, t, 0));
    }

    // --- metadata codec -----------------------------------------------------
    #[test]
    fn meta_json_roundtrip() {
        let m = VaultMeta {
            totp_secret: vec![1, 2, 3, 4],
            backup_hashes: vec!["aa".into(), "bb".into()],
        };
        let parsed = parse_meta_json(&meta_to_json(&m));
        assert_eq!(parsed.totp_secret, m.totp_secret);
        assert_eq!(parsed.backup_hashes, m.backup_hashes);
    }

    #[test]
    fn parse_meta_json_tolerates_unknown_lines() {
        let want = vec![9u8, 8, 7];
        let b32 = BASE32_NOPAD.encode(&want); // NOPAD: no '=' padding allowed
        let m = parse_meta_json(&format!("noise\nnotbackup: x\ntotp: {b32}\n"));
        assert_eq!(m.totp_secret, want);
        assert!(m.backup_hashes.is_empty());
    }

    #[test]
    fn sha256_known_vector() {
        assert_eq!(
            sha256_hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    // --- version filenames --------------------------------------------------
    #[test]
    fn version_names_are_fixed_width_and_sortable() {
        let a = version_file_name();
        let b = version_file_name();
        assert_eq!(a.len(), b.len(), "all version stamps must be same width");
        // "<ISO stamp with dashes>.<9-digit nanos>" — the fixed-width numeric
        // suffix keeps lexicographic order equal to chronological order.
        let dot = a.len() - 10;
        assert_eq!(&a[dot..dot + 1], ".");
        assert!(a[dot + 1..].bytes().all(|c| c.is_ascii_digit()));
    }
}
