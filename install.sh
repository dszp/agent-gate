#!/usr/bin/env bash
# Symlink the commands into ~/.local/bin and seed the config dir. Never overwrites.
set -euo pipefail
HERE="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
BIN="${AGENT_GATE_BIN_DIR:-$HOME/.local/bin}"
CONF="${XDG_CONFIG_HOME:-$HOME/.config}/agent-gate"
mkdir -p "$BIN" "$CONF/gates.d" "$CONF/1p"
for b in unlock lock gate-ssh 1p; do
    if [[ -e "$BIN/$b" && ! -L "$BIN/$b" ]]; then echo "skip: $BIN/$b exists and is not a symlink" >&2; continue; fi
    ln -sfn "$HERE/bin/$b" "$BIN/$b"; echo "linked $BIN/$b"
done
if [[ ! -e "$CONF/config" ]]; then cp "$HERE/examples/config" "$CONF/config"; chmod 600 "$CONF/config"; echo "seeded $CONF/config"; fi
chmod 700 "$CONF" "$CONF/1p"
cat <<EOF

Next:
  1. Edit $CONF/config (key path, op binary, your name).
  2. ssh-keygen -t ed25519 -f ~/.ssh/agent-gate   # set a passphrase; add the .pub to your hosts
  3. unlock ssh          # then the agent uses: gate-ssh user@host 'cmd'
  4. 1p enroll <profile> # optional: 1Password service-account gate
Docs: $HERE/README.md, $HERE/docs/security-model.md
EOF
