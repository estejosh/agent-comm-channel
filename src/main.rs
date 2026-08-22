//! agent-comm-channel — a Git repository used as an asynchronous message bus so
//! that agents running on different PCs can send each other directions and
//! responses.
//!
//! Design in one paragraph
//! -----------------------
//! Every message is a *new, uniquely named file* under `messages/`. Nothing is
//! ever edited in place, so concurrent senders never produce content-level merge
//! conflicts — at worst two pushes race at the ref level, which
//! `git pull --rebase` resolves automatically. Receiving is just: pull, scan
//! `messages/` for files addressed to me that I have not seen yet, and record
//! their ids in a local (gitignored) seen-set.
//!
//! `PROTOCOL.md` is the canonical spec. This binary is the reference client; any
//! language that can write a file and shell out to `git` can interoperate.

mod secrets;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{exit, Command};
use std::thread::sleep;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const VALID_TYPES: &[&str] = &["directive", "response", "status", "ack", "note"];

// ------------------------------------------------------------------ repo paths
fn repo_root() -> PathBuf {
    // The binary lives in target/…; the repo is wherever `.node` / `messages`
    // are. Walk up from CWD until we find a `messages/` dir or a `.git`.
    let mut dir = std::env::current_dir().expect("cwd");
    loop {
        if dir.join("messages").is_dir() || dir.join(".git").exists() {
            return dir;
        }
        if !dir.pop() {
            return std::env::current_dir().expect("cwd");
        }
    }
}

fn messages_dir(root: &Path) -> PathBuf {
    root.join("messages")
}
fn state_dir(root: &Path) -> PathBuf {
    root.join(".state")
}
fn node_file(root: &Path) -> PathBuf {
    root.join(".node")
}

// ------------------------------------------------------------------------ git
fn git(root: &Path, args: &[&str]) -> (bool, String, String) {
    let out = Command::new("git").arg("-C").arg(root).args(args).output();
    match out {
        Ok(o) => (
            o.status.success(),
            String::from_utf8_lossy(&o.stdout).into_owned(),
            String::from_utf8_lossy(&o.stderr).into_owned(),
        ),
        Err(e) => (false, String::new(), e.to_string()),
    }
}

fn pull(root: &Path) {
    git(root, &["pull", "--rebase", "--autostash"]);
}

fn push_with_retry(root: &Path, msg: &str) {
    git(root, &["add", "messages"]);
    // `--quiet` exits 0 (success=true) when there is NOTHING staged.
    let (clean, _, _) = git(root, &["diff", "--cached", "--quiet"]);
    if clean {
        return; // nothing to commit (e.g. duplicate write produced no change)
    }
    git(root, &["commit", "-m", msg]);
    for i in 0..5 {
        pull(root);
        let (ok, _, err) = git(root, &["push"]);
        if ok {
            return;
        }
        if i == 4 {
            eprintln!("push failed after 5 attempts:\n{err}");
            exit(1);
        }
        sleep(Duration::from_millis(1500 * (i as u64 + 1)));
    }
}

// ----------------------------------------------------------------------- utils
fn now_iso() -> String {
    // Minimal UTC ISO-8601 without pulling in chrono.
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let (y, mo, d, h, mi, s) = civil_from_unix(secs as i64);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// Convert a Unix timestamp to (year, month, day, hour, min, sec) in UTC.
/// Algorithm from Howard Hinnant's `civil_from_days`.
fn civil_from_unix(secs: i64) -> (i64, i64, i64, i64, i64, i64) {
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
    (y, m, d, h, mi, s)
}

fn slug(s: &str) -> String {
    let out: String = s
        .to_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let out = out.trim_matches('-').to_string();
    if out.is_empty() {
        "node".into()
    } else {
        out
    }
}

fn short_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..8].to_string()
}

fn node_id(root: &Path, cli: &Option<String>) -> String {
    if let Some(n) = cli {
        return slug(n);
    }
    match fs::read_to_string(node_file(root)) {
        // Slug on read too: .node is an untracked local file a user can hand-edit,
        // and the raw value ends up inside message filenames (PROTOCOL.md §4.1).
        // Normalizing here keeps every emitted path within messages/ and .state/.
        Ok(s) => slug(s.trim()),
        Err(_) => {
            eprintln!("no node id: run `channel init --node <name>` first");
            exit(1);
        }
    }
}

/// Like `node_id` but returns None instead of exiting when `.node` is absent.
fn node_id_opt(root: &Path) -> Option<String> {
    fs::read_to_string(node_file(root))
        .ok()
        .map(|s| slug(s.trim()))
}

// --------------------------------------------------------------------- message
#[derive(Default, Clone)]
struct Message {
    id: String,
    from: String,
    to: String,
    typ: String,
    created: String,
    thread: Option<String>,
    in_reply_to: Option<String>,
    body: String,
}

fn parse_message(path: &Path) -> Option<Message> {
    let text = fs::read_to_string(path).ok()?;
    let mut m = Message::default();
    let body;
    if let Some(rest) = text.strip_prefix("---") {
        // rest = "<frontmatter>---<body>"
        if let Some(idx) = rest.find("---") {
            let fm = &rest[..idx];
            body = rest[idx + 3..].trim().to_string();
            for line in fm.lines() {
                if let Some((k, v)) = line.split_once(':') {
                    let (k, v) = (k.trim(), v.trim().to_string());
                    match k {
                        "id" => m.id = v,
                        "from" => m.from = v,
                        "to" => m.to = v,
                        "type" => m.typ = v,
                        "created" => m.created = v,
                        "thread" => m.thread = Some(v),
                        "in_reply_to" => m.in_reply_to = Some(v),
                        _ => {}
                    }
                }
            }
        } else {
            body = text;
        }
    } else {
        body = text;
    }
    m.body = body;
    Some(m)
}

fn all_messages(root: &Path) -> Vec<Message> {
    let dir = messages_dir(root);
    // Sort by `created`, tie-broken by FILENAME so equal timestamps still get a
    // machine-independent total order (`read_dir` order is arbitrary).
    let mut out: Vec<(String, Message)> = match fs::read_dir(&dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("md"))
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                parse_message(&e.path()).map(|m| (name, m))
            })
            .collect(),
        Err(_) => vec![],
    };
    out.sort_by(|a, b| (&a.1.created, &a.0).cmp(&(&b.1.created, &b.0)));
    out.into_iter().map(|(_, m)| m).collect()
}

fn seen_path(root: &Path, node: &str) -> PathBuf {
    state_dir(root).join(format!("{}.seen", slug(node)))
}

fn load_seen(root: &Path, node: &str) -> BTreeSet<String> {
    match fs::read_to_string(seen_path(root, node)) {
        Ok(s) => s
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect(),
        Err(_) => BTreeSet::new(),
    }
}

fn save_seen(root: &Path, node: &str, seen: &BTreeSet<String>) {
    let _ = fs::create_dir_all(state_dir(root));
    let body: String = seen.iter().cloned().collect::<Vec<_>>().join("\n");
    let _ = fs::write(seen_path(root, node), body + "\n");
}

// --------------------------------------------------------------------- printing
fn print_message(m: &Message, oneline: bool) {
    let head = format!(
        "{}  {} -> {}  [{}]  {}",
        m.created, m.from, m.to, m.typ, m.id
    );
    if oneline {
        let first = m.body.lines().next().unwrap_or("");
        let first: String = first.chars().take(70).collect();
        println!("{head}  |  {first}");
    } else {
        println!("{}", "=".repeat(72));
        println!("{head}");
        if let Some(t) = &m.thread {
            let reply = m
                .in_reply_to
                .as_ref()
                .map(|r| format!("  in_reply_to: {r}"))
                .unwrap_or_default();
            println!("thread: {t}{reply}");
        }
        println!("{}", "-".repeat(72));
        println!("{}", m.body);
        println!();
    }
}

// ----------------------------------------------------------------------- cmds
fn cmd_init(root: &Path, node: &str) {
    let node = slug(node);
    let _ = fs::create_dir_all(messages_dir(root));
    let _ = fs::create_dir_all(state_dir(root));
    let _ = fs::write(node_file(root), format!("{node}\n"));
    println!("this node is now '{node}' (written to .node)");
}

#[allow(clippy::too_many_arguments)]
fn cmd_send(
    root: &Path,
    node: &str,
    to: &str,
    typ: &str,
    thread: Option<String>,
    in_reply_to: Option<String>,
    body: String,
) {
    if !VALID_TYPES.contains(&typ) {
        eprintln!("--type must be one of {VALID_TYPES:?}");
        exit(1);
    }
    pull(root);
    let id = short_id();
    let created = now_iso();
    let to = if to == "all" {
        "all".to_string()
    } else {
        slug(to)
    };
    let stamp = created.replace(':', "-");
    let path = messages_dir(root).join(format!("{stamp}__{node}__{id}.md"));

    let mut fm =
        format!("---\nid: {id}\nfrom: {node}\nto: {to}\ntype: {typ}\ncreated: {created}\n");
    if let Some(t) = thread {
        fm.push_str(&format!("thread: {t}\n"));
    }
    if let Some(r) = in_reply_to {
        fm.push_str(&format!("in_reply_to: {r}\n"));
    }
    fm.push_str("---\n\n");
    fm.push_str(body.trim());
    fm.push('\n');

    let _ = fs::create_dir_all(messages_dir(root));
    if fs::write(&path, fm).is_err() {
        eprintln!("failed to write message file");
        exit(1);
    }
    push_with_retry(root, &format!("msg {node} -> {to} [{typ}] {id}"));
    println!("sent {id}  {node} -> {to}  [{typ}]");
}

/// Pull and return the messages addressed to `node` that are not yet in the
/// seen-set. Does not touch the seen-set; callers decide when to mark.
fn fresh_messages(root: &Path, node: &str) -> Vec<Message> {
    pull(root);
    let seen = load_seen(root, node);
    all_messages(root)
        .into_iter()
        .filter(|m| !seen.contains(&m.id) && m.from != node && (m.to == node || m.to == "all"))
        .collect()
}

/// Add ids to the per-node seen-set and persist it.
fn mark_seen(root: &Path, node: &str, ids: impl Iterator<Item = String>) {
    let mut seen = load_seen(root, node);
    for id in ids {
        seen.insert(id);
    }
    save_seen(root, node, &seen);
}

/// Print-and-consume receive used by `recv`: prints new messages and marks them
/// seen unless `peek`. `quiet` suppresses the "(no new messages)" line (watch).
fn recv_fresh(root: &Path, node: &str, peek: bool, quiet: bool) -> Vec<Message> {
    let fresh = fresh_messages(root, node);
    if fresh.is_empty() {
        if !quiet {
            println!("(no new messages)");
        }
        return fresh;
    }
    for m in &fresh {
        print_message(m, false);
    }
    if !peek {
        mark_seen(root, node, fresh.iter().map(|m| m.id.clone()));
    }
    fresh
}

fn cmd_recv(root: &Path, node: &str, peek: bool) {
    recv_fresh(root, node, peek, false);
}

/// Run `exec` once for `m` with the message exposed via environment so a hook
/// (an agent trigger, a script) can act on it without a human in the loop:
///   CHANNEL_ID, CHANNEL_FROM, CHANNEL_TO, CHANNEL_TYPE, CHANNEL_CREATED,
///   CHANNEL_THREAD, CHANNEL_IN_REPLY_TO, CHANNEL_BODY
/// Returns true only if the hook ran and exited 0.
fn run_exec(exec: &str, m: &Message) -> bool {
    // Shell out via the platform shell so `exec` can be an arbitrary command line.
    #[cfg(windows)]
    let mut cmd = {
        let mut c = Command::new("cmd");
        c.arg("/C").arg(exec);
        c
    };
    #[cfg(not(windows))]
    let mut cmd = {
        let mut c = Command::new("sh");
        c.arg("-c").arg(exec);
        c
    };
    cmd.env("CHANNEL_ID", &m.id)
        .env("CHANNEL_FROM", &m.from)
        .env("CHANNEL_TO", &m.to)
        .env("CHANNEL_TYPE", &m.typ)
        .env("CHANNEL_CREATED", &m.created)
        .env("CHANNEL_THREAD", m.thread.clone().unwrap_or_default())
        .env(
            "CHANNEL_IN_REPLY_TO",
            m.in_reply_to.clone().unwrap_or_default(),
        )
        .env("CHANNEL_BODY", &m.body);
    match cmd.status() {
        Ok(s) if s.success() => true,
        Ok(s) => {
            eprintln!("[watch] exec hook exited with {s} for message {}", m.id);
            false
        }
        Err(e) => {
            eprintln!("[watch] failed to run exec hook: {e}");
            false
        }
    }
}

/// Auto-pull loop: polls forever so a human never has to trigger a sync. Survives
/// transient git/network failures (a failed pull just yields no new messages this
/// tick; the next tick retries). With `--exec`, fires a hook per new message.
///
/// Delivery with `--exec` is at-least-once: a message is marked seen only after
/// its hook exits 0, so a crash or a failing handler simply retries next tick.
/// Handlers should therefore tolerate redelivery of the same message id.
fn cmd_watch(root: &Path, node: &str, interval: u64, exec: Option<String>) {
    let interval = interval.max(1);
    let hook = exec
        .as_deref()
        .map(|e| format!(" -> exec: {e}"))
        .unwrap_or_default();
    println!("watching as '{node}' every {interval}s{hook} — Ctrl-C to stop");
    loop {
        let fresh = fresh_messages(root, node);
        match &exec {
            None => {
                for m in &fresh {
                    print_message(m, false);
                }
                if !fresh.is_empty() {
                    mark_seen(root, node, fresh.iter().map(|m| m.id.clone()));
                }
            }
            Some(e) => {
                let delivered: Vec<String> = fresh
                    .iter()
                    .filter(|m| {
                        print_message(m, false);
                        run_exec(e, m)
                    })
                    .map(|m| m.id.clone())
                    .collect();
                mark_seen(root, node, delivered.into_iter());
            }
        }
        sleep(Duration::from_secs(interval));
    }
}

fn cmd_log(root: &Path, limit: usize) {
    // Pull first: `log` promises recent traffic from EVERYONE, which requires
    // seeing other nodes' commits, not just whatever this clone already has.
    pull(root);
    let all = all_messages(root);
    let start = all.len().saturating_sub(limit);
    for m in &all[start..] {
        print_message(m, true);
    }
}

// ----------------------------------------------------------------------- args
fn opt(args: &[String], key: &str) -> Option<String> {
    args.iter()
        .position(|a| a == key)
        .and_then(|i| args.get(i + 1).cloned())
}

fn has_flag(args: &[String], key: &str) -> bool {
    args.iter().any(|a| a == key)
}

/// The first argument that is not a flag and not a flag's value.
fn positional(args: &[String], flags_with_values: &[&str]) -> Option<String> {
    let mut skip = false;
    for a in args {
        if skip {
            skip = false;
            continue;
        }
        if a.starts_with("--") {
            if flags_with_values.contains(&a.as_str()) {
                skip = true;
            }
            continue;
        }
        return Some(a.clone());
    }
    None
}

fn usage() -> ! {
    eprintln!(
        "channel — Git-backed inter-PC agent message bus\n\
         \n\
         USAGE:\n\
         \x20 channel init  --node <name>\n\
         \x20 channel send  --to <node|all> [--type directive|response|status|ack|note]\n\
         \x20               [--thread <id>] [--in-reply-to <id>] \"message body\"\n\
         \x20 channel recv  [--peek] [--node <name>]\n\
         \x20 channel watch [--interval <secs>] [--exec <cmd>] [--node <name>]\n\
         \x20 channel log   [--limit <n>]\n\
         \x20 channel whoami\n\
         \x20 channel secret enroll --node <id> | set <name> [val] | get <name> | list   (git tier, agent-usable)\n\
         \x20 channel vault init | set <name> [val] | get <name> | list | unlock [--minutes N] | lock   (local 2FA vault)\n\
         \n\
          The node id is read from .node (set by `init`) unless --node is given.\n\
          Omit the send body argument to read the body from stdin.\n\
          See PROTOCOL.md for the on-disk wire format."
    );
    exit(2);
}

fn main() {
    let root = repo_root();
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.is_empty() {
        usage();
    }
    let cmd = argv[0].clone();
    let rest = &argv[1..];
    let node_cli = opt(rest, "--node");

    match cmd.as_str() {
        "init" => {
            let node = opt(rest, "--node").unwrap_or_else(|| {
                eprintln!("init requires --node <name>");
                exit(2);
            });
            cmd_init(&root, &node);
        }
        "send" => {
            let node = node_id(&root, &node_cli);
            let to = opt(rest, "--to").unwrap_or_else(|| {
                eprintln!("send requires --to <node|all>");
                exit(2);
            });
            let typ = opt(rest, "--type").unwrap_or_else(|| "note".into());
            let thread = opt(rest, "--thread");
            let in_reply_to = opt(rest, "--in-reply-to");
            let body = positional(
                rest,
                &["--to", "--type", "--thread", "--in-reply-to", "--node"],
            )
            .unwrap_or_else(|| {
                // fall back to stdin
                use std::io::Read;
                let mut s = String::new();
                let _ = std::io::stdin().read_to_string(&mut s);
                s
            });
            cmd_send(&root, &node, &to, &typ, thread, in_reply_to, body);
        }
        "recv" => {
            let node = node_id(&root, &node_cli);
            cmd_recv(&root, &node, has_flag(rest, "--peek"));
        }
        "watch" => {
            let node = node_id(&root, &node_cli);
            let interval = opt(rest, "--interval")
                .and_then(|s| s.parse().ok())
                .unwrap_or(30);
            let exec = opt(rest, "--exec");
            cmd_watch(&root, &node, interval, exec);
        }
        "log" => {
            let limit = opt(rest, "--limit")
                .and_then(|s| s.parse().ok())
                .unwrap_or(20);
            cmd_log(&root, limit);
        }
        "whoami" => {
            println!("{}", node_id(&root, &node_cli));
        }
        "vault" => {
            let sub = rest.first().map(|s| s.as_str()).unwrap_or("");
            let rest2 = if rest.is_empty() { &[][..] } else { &rest[1..] };
            match sub {
                "init" => secrets::vault_init(),
                "set" => {
                    let name = positional(rest2, &[]).unwrap_or_else(|| {
                        eprintln!("vault set requires <name>");
                        exit(2);
                    });
                    // value: an explicit second positional, else read from stdin
                    let value = rest2
                        .iter()
                        .filter(|a| !a.starts_with("--"))
                        .nth(1)
                        .cloned();
                    secrets::vault_set(&name, value);
                }
                "get" => {
                    let name = positional(rest2, &[]).unwrap_or_else(|| {
                        eprintln!("vault get requires <name>");
                        exit(2);
                    });
                    secrets::vault_get(&name);
                }
                "list" => secrets::vault_list(),
                "unlock" => {
                    let mins = opt(rest2, "--minutes")
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(15);
                    secrets::vault_unlock(mins);
                }
                "lock" => secrets::vault_lock(),
                _ => {
                    eprintln!(
                        "vault subcommands: init | set <name> [value] | get <name> | list | unlock [--minutes N] | lock"
                    );
                    exit(2);
                }
            }
        }
        "secret" => {
            let sub = rest.first().map(|s| s.as_str()).unwrap_or("");
            let rest2 = if rest.is_empty() { &[][..] } else { &rest[1..] };
            match sub {
                "enroll" => {
                    let n = opt(rest2, "--node")
                        .or_else(|| node_id_opt(&root))
                        .unwrap_or_else(|| {
                            eprintln!(
                                "secret enroll requires --node <id> (or run `channel init` first)"
                            );
                            exit(2);
                        });
                    secrets::secret_enroll(&n);
                }
                "set" => {
                    let name = positional(rest2, &[]).unwrap_or_else(|| {
                        eprintln!("secret set requires <name>");
                        exit(2);
                    });
                    let value = rest2
                        .iter()
                        .filter(|a| !a.starts_with("--"))
                        .nth(1)
                        .cloned();
                    secrets::secret_set(&name, value);
                }
                "get" => {
                    let name = positional(rest2, &[]).unwrap_or_else(|| {
                        eprintln!("secret get requires <name>");
                        exit(2);
                    });
                    secrets::secret_get(&name);
                }
                "list" => secrets::secret_list(),
                _ => {
                    eprintln!("secret subcommands: enroll --node <id> | set <name> [value] | get <name> | list");
                    exit(2);
                }
            }
        }
        "-h" | "--help" | "help" => usage(),
        other => {
            eprintln!("unknown command: {other}\n");
            usage();
        }
    }
}

// ------------------------------------------------------------------------
//  Tests — pure logic and temp-dir filesystem behavior; no network, no git.
// ------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_root(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "acc-test-{}-{}-{}",
            tag,
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(d.join("messages")).unwrap();
        d
    }

    // --- time ---------------------------------------------------------------
    #[test]
    fn civil_from_unix_known_instants() {
        assert_eq!(civil_from_unix(0), (1970, 1, 1, 0, 0, 0));
        let (y, mo, d, h, mi, s) = civil_from_unix(1_783_180_818);
        assert_eq!((y, mo, d, h, mi, s), (2026, 7, 4, 16, 0, 18));
        // Leap day: 2024-02-29T00:00:00Z == 1_709_164_800
        assert_eq!(civil_from_unix(1_709_164_800), (2024, 2, 29, 0, 0, 0));
    }

    #[test]
    fn now_iso_has_protocol_shape() {
        let t = now_iso();
        assert_eq!(t.len(), 20);
        assert!(t.ends_with('Z'));
        assert_eq!(&t[4..5], "-");
        assert_eq!(&t[10..11], "T");
        assert_eq!(&t[19..20], "Z");
    }

    // --- slug / ids -----------------------------------------------------------
    #[test]
    fn slug_normalizes_node_ids() {
        assert_eq!(slug("Workstation 01"), "workstation-01");
        assert_eq!(slug("pc_alpha"), "pc-alpha");
        assert_eq!(slug("../escape"), "escape"); // path traversal defused
        assert_eq!(slug(""), "node");
        assert_eq!(slug("über-pc"), "ber-pc");
    }

    #[test]
    fn short_id_is_eight_hex() {
        let id = short_id();
        assert_eq!(id.len(), 8);
        assert!(id.bytes().all(|c| c.is_ascii_hexdigit()));
    }

    // --- parser -----------------------------------------------------------------
    #[test]
    fn parse_message_full_frontmatter() {
        let root = tmp_root("parse-full");
        let f = messages_dir(&root).join("x.md");
        fs::write(
            &f,
            "---\nid: abcd1234\nfrom: pc-a\nto: pc-b\ntype: directive\ncreated: 2026-07-04T16:00:18Z\nthread: t-1\nin_reply_to: 9f3a1c02\n---\n\nhello world\n",
        )
        .unwrap();
        let m = parse_message(&f).unwrap();
        assert_eq!(m.id, "abcd1234");
        assert_eq!(m.from, "pc-a");
        assert_eq!(m.to, "pc-b");
        assert_eq!(m.typ, "directive");
        assert_eq!(m.created, "2026-07-04T16:00:18Z");
        assert_eq!(m.thread.as_deref(), Some("t-1"));
        assert_eq!(m.in_reply_to.as_deref(), Some("9f3a1c02"));
        assert_eq!(m.body, "hello world");
    }

    #[test]
    fn parse_message_ignores_unknown_keys_and_handles_junk() {
        let root = tmp_root("parse-junk");
        let f = messages_dir(&root).join("u.md");
        fs::write(
            &f,
            "---\nid: 11111111\nfrom: a\nto: b\ntype: note\ncreated: 2026-07-04T16:00:18Z\nsig: Zm9v\nfuture_key: whatever\n---\n\nbody\n---\nwith rule\n",
        )
        .unwrap();
        let m = parse_message(&f).unwrap();
        assert_eq!(m.id, "11111111");
        assert_eq!(m.typ, "note"); // unknown keys must not break parsing
        assert!(m.body.starts_with("body"));

        // No frontmatter at all: whole file is body, fields default empty.
        let g = messages_dir(&root).join("plain.md");
        fs::write(&g, "just some text\n").unwrap();
        let m2 = parse_message(&g).unwrap();
        // No frontmatter: the file is used verbatim as the body.
        assert_eq!(m2.body, "just some text\n");
        assert_eq!(m2.id, "");
    }

    // --- seen-set + delivery filter ---------------------------------------------
    fn write_msg(root: &Path, name: &str, from: &str, to: &str, id: &str, created: &str) {
        let f = messages_dir(root).join(format!("{name}.md"));
        fs::write(
            &f,
            format!("---\nid: {id}\nfrom: {from}\nto: {to}\ntype: note\ncreated: {created}\n---\n\nbody {id}\n"),
        )
        .unwrap();
    }

    #[test]
    fn fresh_messages_filters_recipient_seen_and_self() {
        let root = tmp_root("fresh-filter");
        write_msg(&root, "a", "pc-x", "me", "aaaaaaaa", "2026-07-04T16:00:01Z");
        write_msg(
            &root,
            "b",
            "pc-y",
            "all",
            "bbbbbbbb",
            "2026-07-04T16:00:02Z",
        );
        write_msg(&root, "c", "me", "me", "cccccccc", "2026-07-04T16:00:03Z"); // from me -> skip
        write_msg(
            &root,
            "d",
            "pc-z",
            "other",
            "dddddddd",
            "2026-07-04T16:00:04Z",
        ); // not for me -> skip

        let fresh = fresh_messages(&root, "me");
        let ids: Vec<&str> = fresh.iter().map(|m| m.id.as_str()).collect();
        assert_eq!(ids, vec!["aaaaaaaa", "bbbbbbbb"]);

        // Mark one seen; it must disappear on the next pass.
        mark_seen(&root, "me", ["aaaaaaaa".to_string()].into_iter());
        let fresh = fresh_messages(&root, "me");
        let ids: Vec<&str> = fresh.iter().map(|m| m.id.as_str()).collect();
        assert_eq!(ids, vec!["bbbbbbbb"]);
    }

    #[test]
    fn equal_created_timestamps_order_by_filename_deterministically() {
        let root = tmp_root("tie-break");
        // Same `created` on both; only filenames differ. read_dir order is
        // arbitrary, so this only passes if the filename tie-break works.
        write_msg(
            &root,
            "zz-later-name",
            "a",
            "b",
            "22222222",
            "2026-07-04T16:00:00Z",
        );
        write_msg(
            &root,
            "aa-early-name",
            "a",
            "b",
            "11111111",
            "2026-07-04T16:00:00Z",
        );
        for _ in 0..5 {
            let all = all_messages(&root);
            assert_eq!(all[0].id, "11111111");
            assert_eq!(all[1].id, "22222222");
        }
    }

    #[test]
    fn seen_set_survives_reload_and_sorts_stably() {
        let root = tmp_root("seen-roundtrip");
        mark_seen(
            &root,
            "n1",
            ["22222222".to_string(), "11111111".to_string()].into_iter(),
        );
        let seen = load_seen(&root, "n1");
        assert_eq!(seen.len(), 2);
        assert!(seen.contains("11111111") && seen.contains("22222222"));
        // Per-node isolation.
        assert!(load_seen(&root, "n2").is_empty());
    }

    #[test]
    fn all_messages_sort_by_created_then_read_order_is_stable() {
        let root = tmp_root("sort");
        fs::create_dir_all(messages_dir(&root)).unwrap();
        write_msg(&root, "later", "a", "b", "11111111", "2026-07-04T16:00:18Z");
        fs::write(messages_dir(&root).join("early.md"), "---\nid: 22222222\nfrom: a\nto: b\ntype: note\ncreated: 2026-07-01T00:00:00Z\n---\n\nx\n").unwrap();
        let all = all_messages(&root);
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].created, "2026-07-01T00:00:00Z");
    }
}
