# PROTOCOL — the agent-comm-channel wire format

This document, **not the Rust binary**, is the source of truth. Any program in any
language that can (a) read/write files in a directory and (b) run `git` can
participate as a full peer. The Rust `channel` binary is the reference client;
a Python script, a bash one-liner, or an agent with plain filesystem + git access
can interoperate with it as long as it follows the rules below.

## 1. Transport

A single Git repository is the message bus. There is no server. Peers exchange
messages by committing new files and pushing; they receive by pulling and reading.

- **Send** = write a new file under `messages/`, `git add` it, `git commit`,
  `git pull --rebase`, `git push` (retry the pull/push on rejection).
- **Receive** = `git pull --rebase`, then scan `messages/` for files addressed to
  you that you have not already processed.

## 2. The append-only rule (this is what prevents merge conflicts)

**Every message is a brand-new file with a globally-unique name. Messages are never
edited or deleted once written.**

Because two peers writing at the same time always create *different* files, there is
never a content-level merge conflict. The only possible collision is at the Git ref
level (two pushes racing), and `git pull --rebase` followed by a re-push resolves it
mechanically — no human, no conflict markers. Clients SHOULD retry push a few times
with a short backoff.

Corollary: correcting or retracting a message is done by sending a *new* message
(e.g. `type: note` referencing the old id via `in_reply_to`), never by editing.

**Duplicate ids.** Ids are 8 random hex chars, so collisions are negligible but
MUST be tolerated: if two distinct files ever carry the same `id`, receivers
process the first they encounter and ignore the rest (first-seen wins). A file
that is an exact byte-for-byte duplicate causes no conflict at all — Git treats
it as the same blob, and `git add` simply has nothing new to commit.

## 3. Node identity

Each PC is a **node** with a lowercase-kebab id (e.g. `pc-alpha`, `workshop-rig`).
The reference client stores it in `.node` (gitignored — it is per-machine, not
shared). Any string matching `[a-z0-9-]+` is a valid node id. `all` is reserved as
the broadcast recipient and MUST NOT be used as a node id.

## 4. Message file

### 4.1 Filename

```
messages/<CREATED>__<FROM>__<ID>.md
```

- `<CREATED>` — the `created` timestamp with `:` replaced by `-`
  (e.g. `2026-07-04T16-00-18Z`). Keeps files chronologically sortable by name.
- `<FROM>` — the sender node id.
- `<ID>` — the 8-hex-char message id.

Example: `2026-07-04T16-00-18Z__pc-alpha__5b7cca88.md`

### 4.2 Contents

YAML-ish frontmatter between `---` fences, then a Markdown body:

```markdown
---
id: 5b7cca88
from: pc-alpha
to: pc-beta
type: directive
created: 2026-07-04T16:00:18Z
thread: t-0007          # optional
in_reply_to: 9f3a1c02   # optional
---

Free-form Markdown body. This is what the receiving agent reads and acts on.
```

Field rules:

| field         | required | value                                                            |
|---------------|----------|------------------------------------------------------------------|
| `id`          | yes      | 8 lowercase hex chars, unique per message                        |
| `from`        | yes      | sender node id                                                    |
| `to`          | yes      | a node id, or `all` for broadcast                                |
| `type`        | yes      | one of `directive`, `response`, `status`, `ack`, `note`          |
| `created`     | yes      | UTC ISO-8601, `YYYY-MM-DDTHH:MM:SSZ`                              |
| `thread`      | no       | opaque id grouping a conversation                                |
| `in_reply_to` | no       | the `id` of the message this responds to                         |

The parser is intentionally forgiving: split on the first two `---`, read
`key: value` lines, treat everything after the second `---` as the body. Unknown
frontmatter keys MUST be ignored, not rejected — this is how the format stays
forward-compatible.

Bodies are UTF-8 text. A file with no frontmatter at all is not an error: treat
the whole file as the body and all fields as empty (this keeps a stray or
hand-written file from wedging a receiver). As a courtesy convention, keep
bodies under ~64 KiB — the bus is for directions and responses, not payloads.

### 4.3 Message types

- `directive` — "do this" (an instruction expecting action).
- `response` — the result of acting on a directive.
- `status` — unsolicited state ("node alpha online", "build green").
- `ack` — lightweight "received / seen", no action implied.
- `note` — anything else, including corrections/retractions.

These are conventions for the receiving agent, not enforced by transport.

## 5. The seen-set (per-node receive state)

Each node keeps a local, **gitignored** record of message ids it has already
processed, in `.state/<node>.seen` (the reference client uses one id per line).
Because it is not committed, every node has its own independent view of "new".

Receive algorithm:

```
git pull --rebase --autostash
for each file in messages/*.md, sorted by `created` (ties broken by filename):
    parse it
    if id not in my seen-set
       and from != me
       and (to == me or to == "all"):
        deliver it to the agent
        add id to my seen-set
persist seen-set
```

The filename tie-break matters: `created` comes from each sender's clock, so two
messages can share a timestamp, and `read_dir` order is arbitrary. Sorting by
(`created`, filename) gives every node the same total order.

## 6. Minimal interop example (no reference client)

A conformant *send* in bash:

```bash
id=$(openssl rand -hex 4)
now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
f="messages/${now//:/-}__pc-gamma__${id}.md"
cat > "$f" <<EOF
---
id: $id
from: pc-gamma
to: pc-alpha
type: response
created: $now
---

done — rebuilt and restarted.
EOF
git add "$f" && git commit -qm "msg $id" && git pull --rebase -q && git push -q
```

That is the entire protocol. If your program produces files like the above and
reads them back per §5, it is a first-class peer alongside the Rust binary.

## 7. Security note

This channel is only as private as the Git repository hosting it. The public
reference repo is a *format and toolkit*; run real coordination on a **private**
repository (see the companion `pc-agent-bridge`). Anyone with push access to the
repo can send messages as any node id — there is no authentication in the transport
itself. If you need sender authenticity, sign message bodies (e.g. Ed25519) and
verify on receipt; the frontmatter is designed to carry a `sig` field if you add
one (unknown keys are ignored by conformant parsers). The recommended convention:
`sig` is the signature over the exact UTF-8 body bytes, with the signer's node id
in `from` — frontmatter is left unsigned so a message can be relayed unchanged.

## 8. Ordering, delivery semantics, and failure modes

### 8.1 Ordering is advisory

There is no global order. `created` uses each sender's wall clock, which can be
wrong or skewed; filenames inherit that skew. Consumers sort messages into a
stable order (§5), but protocols built on top of this bus MUST NOT rely on
cross-node ordering — use `thread`, `in_reply_to`, and explicit state in message
bodies instead.

### 8.2 Delivery semantics

- Plain `recv` is **at-most-once** per node: a message is marked seen the moment
  it is printed.
- `watch --exec` is **at-least-once**: a message stays unseen until its hook
  exits 0, so crashes and failing handlers retry on later ticks. Handlers MUST
  therefore tolerate seeing the same message id more than once (be idempotent).
  Losing the seen-set has the same effect: redelivery, not data loss.

### 8.3 Failure modes and recovery

| failure                              | what happens                                   | recovery                                              |
|--------------------------------------|------------------------------------------------|-------------------------------------------------------|
| crash between commit and push        | local commit exists, origin does not           | nothing to do — the next send/push carries it along    |
| two peers push concurrently          | loser's push rejected (non-fast-forward)       | `git pull --rebase` + re-push; clients SHOULD auto-retry with backoff |
| push fails repeatedly (offline)      | message sits in local commits                  | retried on next send tick; Git queues it durably       |
| receiver sees malformed file         | parser treats it as body-only/empty fields     | skip it; never let one bad file wedge the receive loop |
| duplicate message id                 | second file ignored (first-seen wins)          | none needed                                            |
| seen-set lost/deleted                | all history looks "new" again                  | redelivery only; handlers should be idempotent (§8.2)  |

A crashed `send` never corrupts anything: at worst it leaves an unpushed local
commit or an uncommitted file, both of which are picked up by the next attempt.
