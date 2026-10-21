# agent-gate

## What it is

agent-gate is a set of shell commands that let an AI agent use SSH keys, 1Password, and other secrets without ever holding them itself. The owner unlocks a gate by typing a passphrase for a limited time; while it's unlocked, the agent can use the secret through a small set of wrapper commands, and once it expires (or the owner locks it early) the agent has nothing again. See [`docs/security-model.md`](docs/security-model.md) for what this does and doesn't protect against.

## Requirements

Bash ≥ 4.4, GNU coreutils (`readlink -f`, `stat`, `shred`, `timeout`), `openssl`, and `ssh`. A systemd user session is optional but recommended — without it, autolock timers can't be scheduled and you should run `lock` by hand (see [`docs/security-model.md`](docs/security-model.md)). Running the tests additionally needs `python3`.

## Install

```bash
git clone <this-repo> agent-gate && cd agent-gate
./install.sh
```

`install.sh` symlinks `unlock`, `lock`, `gate-ssh`, and `1p` into `~/.local/bin` (make sure that's on your `PATH`) and seeds `~/.config/agent-gate/config` from the example. For each of those names, it replaces an existing symlink but skips (and warns about) an existing regular file. After it runs, follow its own printed next steps:

1. Edit `~/.config/agent-gate/config` (key path, `op` binary, your name).
2. `ssh-keygen -t ed25519 -f ~/.ssh/agent-gate`. Set a passphrase, then add the `.pub` to the hosts the agent should reach.
3. `unlock ssh`, then the agent uses `gate-ssh user@host 'cmd'`.
4. `1p enroll <profile>`, optional: adds a 1Password service-account gate.

## Daily use

The owner runs these. They all prompt for a passphrase except where noted.

| Command | Does |
|---|---|
| `unlock ssh 1h` | Loads the SSH key into a dedicated agent for 1 hour. |
| `unlock 1p` | Unlocks every enrolled 1Password profile with one passphrase. |
| `unlock all` | Unlocks every gate in the safest order (1Password-backed gates first, then the SSH key): one prompt for `1p`, one for `ssh`, plus one more for each `secret` gate that has to fall back to its enrolled blob because 1Password couldn't be reached. |
| `unlock status` | Shows every registered gate, locked or unlocked, and time remaining. |
| `lock` | Locks every gate immediately. Run `lock <gate>` to lock just one. |

Timeouts accept a bare number of seconds or `Ns`/`Nm`/`Nh`/`Nd`/`Nw` (`15m`, `1h`, `2d`). Leave it off to use `GATE_DEFAULT_TIMEOUT` from the config.

## For the agent

The agent never runs `unlock`. It calls the gated wrappers, which work only while the owner has unlocked the matching gate:

- `gate-ssh user@host 'cmd'`: SSH through the gated key. This is what serves the built-in `ssh` gate — there's no other command for it. It runs `ssh -F /dev/null`, so `~/.ssh/config` is ignored: host aliases, `ProxyJump` and per-host options don't apply. Use the full hostname.
- `1p read op://vault/item/field`: read a 1Password secret (also `inject`, `whoami`, and `item`/`document` get/list/create/edit/delete). `run`, `signin`, and the account-admin verbs stay blocked regardless of unlock state.

If a gate isn't unlocked, the wrapper refuses and names who to ask:

```
LOCKED — no key loaded. Ask the owner to run: unlock ssh [timeout]
```

## Adding your own gate

Copy `examples/gates.d/example-token.sh` to `$GATE_DIR/<name>.sh` (default `~/.config/agent-gate/gates.d/`) and edit it. Each gate file is one `gate_register` line:

```bash
gate_register <name> secret ref='op://Vault/item/field'
```

Then write the encrypted fallback blob once. It's needed only if 1Password can't be reached at unlock time:

```bash
unlock <name> enroll
```

After that, `unlock <name> [timeout]` and `lock <name>` work like any built-in gate, and `unlock status` lists it.

## Config

All settings live in `~/.config/agent-gate/config`. The file itself is optional — every key has a built-in default — and it's only seeded from [`examples/config`](examples/config) on first install as a convenience, commented out, for you to edit.

## Security model

Read [`docs/security-model.md`](docs/security-model.md) before pointing this at an agent you don't fully trust: what makes the SSH gate a hard boundary, why the SSH passphrase must never be stored in 1Password, and what the command allowlists do and don't stop.

## Tests

```bash
bash tests/run.sh
```

Dependency-free: every external binary the gates touch (`ssh-agent`, `ssh-add`, `op`, `systemctl`, `systemd-run`) is stubbed on a temporary `PATH`.

## License

MIT. See [`LICENSE`](LICENSE).
