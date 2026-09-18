# Security model

This describes what agent-gate actually protects, and what it does not. Read it before you wire an agent to a gate, and before you add a new one.

## What a gate is

A gate is a time-boxed grant. The owner creates it by typing a passphrase; after that, the agent can use whatever the gate protects until the grant expires or the owner locks it early.

The passphrase step is the point. An agent's calls run non-interactively: nothing is reading a terminal and waiting for input, so it cannot type the passphrase itself and cannot create the grant on its own. It can only use a grant the owner already made.

## Three kinds, and why they are not equivalent

agent-gate has three gate kinds, and they differ in how hard the boundary is once a grant is active.

**`agent`** loads a passphrase-protected SSH key into a dedicated `ssh-agent`. The agent process signs on request but never exposes the key material: there is no call that returns the private key. The gate protects a capability (sign with this key), not a readable secret.

**`sa`** decrypts a 1Password service-account token into a file the agent's user account can read for the life of the grant, so the agent (via `1p`) can call the real `op` CLI with it.

**`secret`** decrypts an arbitrary token (an API key, for example) into a file the agent's user account can read, the same way.

`sa` and `secret` both put plaintext into a file that the agent's uid can open directly. `agent` never does: the key's bytes stay inside `ssh-agent`, reachable only through its signing protocol.

That difference is the rule for anyone adding a new gate kind: **a gate whose secret is a file the agent can read is a soft boundary; only an agent that refuses to export is hard.**

## Why the SSH passphrase must never live in 1Password

The `agent` gate keeps its hard-boundary property only because the passphrase that unlocks it exists nowhere the agent's uid can read. The moment that passphrase is stored anywhere readable while the gate is active, including inside a 1Password item fetched through `1p`, the property is gone: any process running as that uid could read the passphrase, unlock the key itself, and hold a standing credential with no expiry the owner controls.

`sa` and `secret` don't have this exposure to protect, because their plaintext already lands in a uid-readable file the moment they're unlocked. Storing their source secret in 1Password adds no new hole. That is the entire reason those two gate kinds may be 1Password-backed and `agent` may not: it's not a stylistic choice, it's what keeps one gate hard and the other two soft.

## What the allowlists are, and are not

`bin/1p` and the gate scripts allowlist specific `op` verbs and specific commands. This is policy, not sandboxing. It shapes what a well-behaved agent does through these tools; it does not stop a differently-behaved one.

An agent with ordinary shell access can call `op` or `ssh` directly, with any key or token its uid can already read, bypassing the allowlist entirely. The allowlist only constrains callers that go through it; it grants nothing and revokes nothing at the OS level.

Two consequences follow. First, the gates limit what an *unlocked state* grants and put a clock on it; they don't add a permission an agent didn't already have from its uid. Second, if you're deploying this for an agent you don't fully trust, treat agent-gate as one layer, not the whole answer, and pair it with OS-level isolation: a restricted user account, a container, or an interactive-only sudo path.

## What lands in tmpfs, and when it's scrubbed

`sa` and `secret` write their decrypted plaintext under `$GATE_RT_BASE` (memory-backed storage, by default the user's `XDG_RUNTIME_DIR`), alongside an expiry timestamp. Nothing is written to disk.

Each unlock schedules a timer that runs `lock` for that gate when the grant expires, and every read of a `secret` gate's remaining time re-checks the expiry itself, so an unenforced timer isn't the only thing standing between an agent and a stale credential. Locking early, or letting the timer fire, deletes the token file with `shred -u` (falling back to a plain `rm` if `shred` isn't available) and removes the expiry file. Nothing decrypted by these two gate kinds outlives its grant or survives a reboot.
