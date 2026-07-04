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

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, exit};
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

fn messages_dir(root: &Path) -> PathBuf { root.join("messages") }
fn state_dir(root: &Path) -> PathBuf { root.join(".state") }
fn node_file(root: &Path) -> PathBuf { root.join(".node") }

// ------------------------------------------------------------------------ git
fn git(root: &Path, args: &[&str]) -> (bool, String, String) {
    let out = Command::new("git")
        .arg("-C").arg(root)
        .args(args)
        .output();
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
    let (staged, _, _) = git(root, &["diff", "--cached", "--quiet"]);
    // `--quiet` exits 1 (success=false) when there ARE staged changes.
    if staged {
        return; // nothing staged
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
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
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
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '-' })
        .collect();
    let out = out.trim_matches('-').to_string();
    if out.is_empty() { "node".into() } else { out }
}

fn short_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..8].to_string()
}

fn node_id(root: &Path, cli: &Option<String>) -> String {
    if let Some(n) = cli {
        return slug(n);
    }
    match fs::read_to_string(node_file(root)) {
        Ok(s) => s.trim().to_string(),
        Err(_) => {
            eprintln!("no node id: run `channel init --node <name>` first");
            exit(1);
        }
    }
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
    let mut out: Vec<Message> = match fs::read_dir(&dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("md"))
            .filter_map(|p| parse_message(&p))
            .collect(),
        Err(_) => vec![],
    };
    out.sort_by(|a, b| a.created.cmp(&b.created));
    out
}

fn seen_path(root: &Path, node: &str) -> PathBuf {
    state_dir(root).join(format!("{}.seen", slug(node)))
}

fn load_seen(root: &Path, node: &str) -> BTreeSet<String> {
    match fs::read_to_string(seen_path(root, node)) {
        Ok(s) => s.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect(),
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
            let reply = m.in_reply_to.as_ref().map(|r| format!("  in_reply_to: {r}")).unwrap_or_default();
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
    let to = if to == "all" { "all".to_string() } else { slug(to) };
    let stamp = created.replace(':', "-");
    let path = messages_dir(root).join(format!("{stamp}__{node}__{id}.md"));

    let mut fm = format!(
        "---\nid: {id}\nfrom: {node}\nto: {to}\ntype: {typ}\ncreated: {created}\n"
    );
    if let Some(t) = thread { fm.push_str(&format!("thread: {t}\n")); }
    if let Some(r) = in_reply_to { fm.push_str(&format!("in_reply_to: {r}\n")); }
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

fn cmd_recv(root: &Path, node: &str, peek: bool) {
    pull(root);
    let mut seen = load_seen(root, node);
    let fresh: Vec<Message> = all_messages(root)
        .into_iter()
        .filter(|m| !seen.contains(&m.id) && m.from != node && (m.to == node || m.to == "all"))
        .collect();
    if fresh.is_empty() {
        println!("(no new messages)");
        return;
    }
    for m in &fresh {
        print_message(m, false);
        seen.insert(m.id.clone());
    }
    if !peek {
        save_seen(root, node, &seen);
    }
}

fn cmd_watch(root: &Path, node: &str, interval: u64) {
    println!("watching as '{node}' every {interval}s — Ctrl-C to stop");
    loop {
        cmd_recv(root, node, false);
        sleep(Duration::from_secs(interval));
    }
}

fn cmd_log(root: &Path, limit: usize) {
    let all = all_messages(root);
    let start = all.len().saturating_sub(limit);
    for m in &all[start..] {
        print_message(m, true);
    }
}

// ----------------------------------------------------------------------- args
fn opt(args: &[String], key: &str) -> Option<String> {
    args.iter().position(|a| a == key).and_then(|i| args.get(i + 1).cloned())
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
         \x20 channel watch [--interval <secs>] [--node <name>]\n\
         \x20 channel log   [--limit <n>]\n\
         \x20 channel whoami\n\
         \n\
         The node id is read from .node (set by `init`) unless --node is given.\n\
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
            cmd_watch(&root, &node, interval);
        }
        "log" => {
            let limit = opt(rest, "--limit").and_then(|s| s.parse().ok()).unwrap_or(20);
            cmd_log(&root, limit);
        }
        "whoami" => {
            println!("{}", node_id(&root, &node_cli));
        }
        "-h" | "--help" | "help" => usage(),
        other => {
            eprintln!("unknown command: {other}\n");
            usage();
        }
    }
}
