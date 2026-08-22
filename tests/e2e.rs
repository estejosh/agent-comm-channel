//! End-to-end protocol tests: real git repos on the local filesystem act as the
//! "remote", multiple clones act as different PCs, and the compiled `channel`
//! binary is driven exactly as an agent would drive it.
//!
//! The headline case is the push race (§2 of PROTOCOL.md): two PCs commit
//! concurrently; the loser's push is rejected and MUST recover mechanically via
//! `git pull --rebase` + re-push, with no human and no conflict markers.
//!
//! These tests shell out to `git` and are therefore gated to unix-like hosts.

#![cfg(unix)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

fn unique_ws(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "acc-e2e-{tag}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&d).unwrap();
    d
}

/// Hermetic git environment: no global/system config, fixed identity, so the
/// tests never touch (or depend on) the machine's real git settings.
fn git_env(c: &mut Command) -> &mut Command {
    c.env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_AUTHOR_NAME", "acc-test")
        .env("GIT_AUTHOR_EMAIL", "acc-test@example.invalid")
        .env("GIT_COMMITTER_NAME", "acc-test")
        .env("GIT_COMMITTER_EMAIL", "acc-test@example.invalid")
        .env("HOME", std::env::temp_dir());
    c
}

fn git(ws: &Path, args: &[&str]) {
    let out = git_env(&mut Command::new("git"))
        .current_dir(ws)
        .args(args)
        .output()
        .expect("spawn git");
    assert!(
        out.status.success(),
        "git {:?} failed:\n{}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
}

fn channel(ws: &Path, args: &[&str]) -> Output {
    git_env(&mut Command::new(env!("CARGO_BIN_EXE_channel")))
        .current_dir(ws)
        .args(args)
        .output()
        .expect("spawn channel")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// Extract the 8-hex message id from a successful `send` ("sent <id>  ...").
fn sent_id(out: &Output) -> String {
    let s = stdout(out);
    let rest = s.split("sent ").nth(1).unwrap_or_default();
    rest.split_whitespace()
        .next()
        .unwrap_or_default()
        .to_string()
}

/// A tiny network of PCs: a bare origin plus one clone per node.
struct Net {
    ws: PathBuf,
}
impl Net {
    fn new(tag: &str) -> Self {
        let ws = unique_ws(tag);
        let origin = ws.join("origin.git");
        git(
            &ws,
            &["init", "--bare", "-b", "main", origin.to_str().unwrap()],
        );

        // Seed one commit so clones get upstream tracking (the client pushes
        // with plain `git push`).
        let seed = ws.join("seed");
        fs::create_dir_all(seed.join("messages")).unwrap();
        fs::write(seed.join("messages").join(".gitkeep"), "").unwrap();
        git(&seed, &["init", "-b", "main"]);
        git(&seed, &["add", "."]);
        git(&seed, &["commit", "-qm", "seed"]);
        git(
            &seed,
            &["remote", "add", "origin", origin.to_str().unwrap()],
        );
        git(&seed, &["push", "-qu", "origin", "main"]);

        for pc in ["alpha", "beta"] {
            let dir = ws.join(pc);
            git(
                &ws,
                &[
                    "clone",
                    "-q",
                    origin.to_str().unwrap(),
                    dir.to_str().unwrap(),
                ],
            );
            let out = channel(&dir, &["init", "--node", pc]);
            assert!(out.status.success(), "init {pc}: {}", stderr(&out));
        }
        Net { ws }
    }

    fn pc(&self, name: &str) -> PathBuf {
        self.ws.join(name)
    }

    /// A third PC whose clone goes stale at seed time.
    fn stale_pc(&self, name: &str) -> PathBuf {
        let dir = self.ws.join(name);
        git(
            self.ws.as_path(),
            &[
                "clone",
                "-q",
                self.ws.join("origin.git").to_str().unwrap(),
                dir.to_str().unwrap(),
            ],
        );
        let out = channel(&dir, &["init", "--node", name]);
        assert!(out.status.success());
        dir
    }
}
impl Drop for Net {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.ws);
    }
}

#[test]
fn send_recv_roundtrip_marks_seen_and_broadcast_reaches_everyone() {
    let net = Net::new("roundtrip");
    let alpha = net.pc("alpha");
    let beta = net.pc("beta");

    let out = channel(
        &alpha,
        &[
            "send",
            "--to",
            "beta",
            "--type",
            "directive",
            "pull latest and rebuild",
        ],
    );
    assert!(out.status.success(), "send failed: {}", stderr(&out));
    assert!(stdout(&out).contains("sent"));

    // The wire file landed locally with the documented name shape.
    let names = read_names(&alpha.join("messages"));
    assert!(
        names.iter().any(|f| f.contains("__alpha__")),
        "got: {names:?}"
    );

    // Beta receives it exactly once.
    let out = channel(&beta, &["recv"]);
    assert!(out.status.success(), "recv failed: {}", stderr(&out));
    let got = stdout(&out);
    assert!(got.contains("pull latest and rebuild"), "got: {got}");
    assert!(got.contains("[directive]"));

    // Second pass: the seen-set suppresses redelivery.
    let out = channel(&beta, &["recv"]);
    assert!(stdout(&out).contains("(no new messages)"));

    // Broadcast reaches beta too.
    let out = channel(
        &alpha,
        &["send", "--to", "all", "--type", "status", "alpha online"],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    let out = channel(&beta, &["recv"]);
    assert!(stdout(&out).contains("alpha online"));
}

#[test]
fn log_lists_traffic_without_consuming_it() {
    let net = Net::new("log");
    let out = channel(
        net.pc("alpha").as_path(),
        &["send", "--to", "beta", "--type", "note", "hello log"],
    );
    assert!(out.status.success());

    let out = channel(net.pc("beta").as_path(), &["log", "--limit", "10"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("hello log"));

    // log must NOT mark anything seen — recv still delivers afterwards.
    let out = channel(net.pc("beta").as_path(), &["recv"]);
    assert!(stdout(&out).contains("hello log"));
}

#[test]
fn concurrent_pushes_resolve_mechanically_via_rebase_retry() {
    // PROTOCOL.md §2: both PCs commit "at the same time"; whoever pushes last
    // hits a non-fast-forward and must recover with pull --rebase + re-push,
    // unattended.
    let net = Net::new("race");
    let stale = net.stale_pc("gamma");

    let out = channel(
        net.pc("alpha").as_path(),
        &["send", "--to", "all", "--type", "status", "first"],
    );
    assert!(out.status.success(), "alpha send: {}", stderr(&out));
    let alpha_id = sent_id(&out);

    // The stale clone now sends against an outdated ref: its push is rejected
    // and the CLIENT itself must retry (pull --rebase + push).
    let out = channel(
        stale.as_path(),
        &["send", "--to", "all", "--type", "status", "second"],
    );
    assert!(
        out.status.success(),
        "stale sender lost the race permanently: {}",
        stderr(&out)
    );
    let gamma_id = sent_id(&out);

    // Origin holds BOTH commits; nothing was dropped.
    let out = git_env(&mut Command::new("git"))
        .current_dir(net.ws.join("origin.git"))
        .args(["log", "--oneline", "main"])
        .output()
        .unwrap();
    let log = String::from_utf8_lossy(&out.stdout);
    assert!(
        log.contains(&alpha_id),
        "missing alpha commit {alpha_id}:\n{log}"
    );
    assert!(
        log.contains(&gamma_id),
        "missing gamma commit {gamma_id} after rebase:\n{log}"
    );

    // And a receiver converges on both.
    let out = channel(net.pc("beta").as_path(), &["recv"]);
    let got = stdout(&out);
    assert!(
        got.contains("first") && got.contains("second"),
        "beta saw:\n{got}"
    );
}

#[test]
fn hand_edited_node_file_cannot_escape_messages_dir() {
    // Regression: .node is untracked, so its raw content used to flow straight
    // into message filenames. It must be normalized like any other node id.
    let net = Net::new("traversal");
    let alpha = net.pc("alpha");
    fs::write(alpha.join(".node"), "../../escaped\n").unwrap();

    let out = channel(
        alpha.as_path(),
        &["send", "--to", "all", "--type", "note", "probe"],
    );
    assert!(out.status.success(), "{}", stderr(&out));

    // The message landed INSIDE messages/, under the normalized id.
    let names = read_names(&alpha.join("messages"));
    assert!(
        names.iter().any(|f| f.contains("__escaped__")),
        "got: {names:?}"
    );

    // Nothing leaked into the checkout root as a stray "…__.." path artifact.
    let strays = read_names(&alpha)
        .into_iter()
        .filter(|f| f.contains("__"))
        .count();
    assert_eq!(strays, 0);
}

#[test]
fn malformed_message_files_do_not_wedge_recv() {
    let net = Net::new("malformed");
    let beta = net.pc("beta");

    // Garbage with no frontmatter and an empty file sit next to real mail.
    fs::write(
        beta.join("messages").join("junk.md"),
        "no frontmatter at all\n---\njust dashes\n",
    )
    .unwrap();
    fs::write(beta.join("messages").join("empty.md"), "").unwrap();

    let out = channel(beta.as_path(), &["recv"]);
    assert!(
        out.status.success(),
        "recv crashed on malformed input: {}",
        stderr(&out)
    );
    assert!(stdout(&out).contains("(no new messages)"));
}

#[test]
fn watch_exec_delivers_at_least_once_on_failing_hook() {
    // A hook that fails must NOT consume the message: it stays unseen so a
    // later tick retries it (at-least-once delivery, PROTOCOL.md §5).
    let net = Net::new("watch-retry");
    let beta = net.pc("beta");

    // Alpha sends; BETA watches (a node never receives its own messages).
    let out = channel(
        net.pc("alpha").as_path(),
        &["send", "--to", "all", "--type", "directive", "do the thing"],
    );
    assert!(out.status.success());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let script = beta.join("fail-hook.sh");
        fs::write(&script, "#!/bin/sh\nexit 3\n").unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();

        let mut child = git_env(&mut Command::new(env!("CARGO_BIN_EXE_channel")))
            .current_dir(&beta)
            .args(["watch", "--interval", "1", "--exec"])
            .arg(script.to_str().unwrap())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn watch");

        // Ticks land at ~0s, ~1s, ~2s: expect at least two failing attempts.
        std::thread::sleep(std::time::Duration::from_millis(2600));
        child.kill().unwrap();
        let err = String::from_utf8_lossy(&child.wait_with_output().unwrap().stderr).into_owned();
        let attempts = err.matches("exit status: 3").count();
        assert!(
            attempts >= 2,
            "expected the hook to be retried, stderr was:\n{err}"
        );

        // The message is STILL pending for this node — not consumed by failures.
        let out = channel(beta.as_path(), &["recv", "--peek"]);
        assert!(
            stdout(&out).contains("do the thing"),
            "message was consumed by failing hooks"
        );
    }
}

fn read_names(dir: &Path) -> Vec<String> {
    match fs::read_dir(dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect(),
        Err(_) => vec![],
    }
}
