#!/usr/bin/env bash
# ==============================================================================
# agent-gate — lib/gate-lib.sh
# Sourced by bin/unlock, bin/gate-ssh, bin/1p and by tests. Never executed.
#
# Config, gate registry, timeout parsing and the three gate KINDS:
#   agent   an ssh-agent holding a passphrase-protected key (hard boundary)
#   sa      1Password service-account profiles, owned by `1p`
#   secret  a time-boxed token in tmpfs, from 1Password or an encrypted blob
# See docs/security-model.md for why these three are not the same thing.
# ==============================================================================
set -uo pipefail

GATE_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
: "${GATE_BUILTIN_DIR:=$GATE_LIB_DIR/../gates.d}"

gate_die()  { echo "$*" >&2; exit 2; }

declare -A _GATE_WARNED=()
gate_warn_deprecated() { # <old> <new> — one note per name per process
    [[ -n "${_GATE_WARNED[$1]:-}" ]] && return 0
    _GATE_WARNED[$1]=1
    echo "agent-gate: $1 is deprecated, use $2" >&2
}

# ---- config -------------------------------------------------------------------
gate_conf_load() {
    GATE_CONF="${XDG_CONFIG_HOME:-$HOME/.config}/agent-gate"
    # shellcheck source=/dev/null
    [[ -f "$GATE_CONF/config" ]] && . "$GATE_CONF/config"
    [[ -z "${GATE_OP_BIN:-}" && -n "${OP_BIN:-}" ]] && { gate_warn_deprecated OP_BIN GATE_OP_BIN; GATE_OP_BIN="$OP_BIN"; }
    [[ -z "${GATE_1P_PASSPHRASE:-}" && -n "${CLAUDE_1P_PASSPHRASE:-}" ]] && \
        { gate_warn_deprecated CLAUDE_1P_PASSPHRASE GATE_1P_PASSPHRASE; GATE_1P_PASSPHRASE="$CLAUDE_1P_PASSPHRASE"; }
    : "${GATE_SSH_KEY:=$HOME/.ssh/agent-gate}"
    : "${GATE_SSH_SOCK:=$HOME/.ssh/agent-gate.sock}"
    : "${GATE_OP_BIN:=op}"
    : "${GATE_DEFAULT_TIMEOUT:=30m}"
    : "${GATE_OWNER:=the owner}"
    : "${GATE_RT_BASE:=${XDG_RUNTIME_DIR:-/run/user/$(id -u)}}"
    : "${GATE_DIR:=$GATE_CONF/gates.d}"
    : "${GATE_1P_RT:=$GATE_RT_BASE/agent-gate/1p}"
    export GATE_CONF GATE_SSH_KEY GATE_SSH_SOCK GATE_OP_BIN GATE_DEFAULT_TIMEOUT \
           GATE_OWNER GATE_RT_BASE GATE_DIR GATE_1P_RT
    [[ -n "${GATE_1P_PASSPHRASE:-}" ]] && export GATE_1P_PASSPHRASE
    return 0
}

# ---- registry -----------------------------------------------------------------
GATE_NAMES=()
declare -A _GATE_KIND=() _GATE_OPT=()

gate_register() { # <name> <kind> [key=value ...]
    local name="${1:-}" kind="${2:-}" kv
    [[ "$name" =~ ^[a-z0-9][a-z0-9_-]*$ ]] || gate_die "gate_register: bad gate name '$name'"
    case "$kind" in agent|sa|secret) ;; *) gate_die "gate_register: unknown kind '$kind' for $name (agent|sa|secret)";; esac
    [[ -z "${_GATE_KIND[$name]:-}" ]] || gate_die "gate_register: '$name' registered twice"
    shift 2
    _GATE_KIND[$name]="$kind"; GATE_NAMES+=("$name")
    for kv in "$@"; do
        [[ "$kv" == *=* ]] || gate_die "gate_register $name: expected key=value, got '$kv'"
        _GATE_OPT["$name.${kv%%=*}"]="${kv#*=}"
    done
}
gate_kind() { printf '%s' "${_GATE_KIND[$1]:-}"; }
gate_opt()  { printf '%s' "${_GATE_OPT[$1.$2]:-${3:-}}"; } # <name> <key> [default]
gate_known(){ [[ -n "${_GATE_KIND[$1]:-}" ]]; }

gate_load_gates() { # source built-ins, then private drop-ins (each dir sorted)
    local f
    for f in "$GATE_BUILTIN_DIR"/*.sh; do [[ -e "$f" ]] && . "$f"; done
    for f in "$GATE_DIR"/*.sh; do [[ -e "$f" ]] && . "$f"; done
    return 0
}

# ---- timeouts -----------------------------------------------------------------
gate_parse_timeout() { # <spec> -> seconds; rc=2 on malformed. Mirrors `ssh-add -t`.
    local t="$1" n unit secs
    if [[ "$t" =~ ^([0-9]+)([smhdw]?)$ ]]; then n="${BASH_REMATCH[1]}"; unit="${BASH_REMATCH[2]}"
    else echo "agent-gate: bad timeout '$t' (use 900, 15m, 1h, 2d)" >&2; return 2; fi
    case "$unit" in w) secs=$((n*604800));; d) secs=$((n*86400));; h) secs=$((n*3600));; m) secs=$((n*60));; *) secs="$n";; esac
    [[ "$secs" -gt 0 ]] || { echo "agent-gate: timeout must be > 0 (got '$t')" >&2; return 2; }
    printf '%s' "$secs"
}

gate_timeout_for() { # <name> [explicit] -> effective spec. arg > GATE_<NAME>_TIMEOUT > default
    local name="$1" explicit="${2:-}" up var legacy
    [[ -n "$explicit" ]] && { printf '%s' "$explicit"; return 0; }
    up="$(tr '[:lower:]-' '[:upper:]_' <<<"$name")"; var="GATE_${up}_TIMEOUT"
    [[ -n "${!var:-}" ]] && { printf '%s' "${!var}"; return 0; }
    for legacy in "CLAUDE_${up}_TIMEOUT" $([[ "$name" == ssh ]] && echo CLAUDE_UNLOCK_TIMEOUT); do
        [[ -n "${!legacy:-}" ]] && { gate_warn_deprecated "$legacy" "$var"; printf '%s' "${!legacy}"; return 0; }
    done
    printf '%s' "$GATE_DEFAULT_TIMEOUT"
}

gate_fmt_remaining() { # <seconds> -> "1h 04m" / "12m 30s"
    local s="$1"
    if [[ "$s" -ge 3600 ]]; then printf '%dh %02dm' $(( s / 3600 )) $(( (s % 3600) / 60 ))
    else printf '%dm %02ds' $(( s / 60 )) $(( s % 60 )); fi
}

# ---- kind: secret -------------------------------------------------------------
readonly GATE_OSSL=(-aes-256-cbc -pbkdf2 -iter 600000)

gate_read_pass() { # <label> -> passphrase on stdout. GATE_1P_PASSPHRASE is the automation/test hook.
    if [[ -n "${GATE_1P_PASSPHRASE:-}" ]]; then printf '%s' "$GATE_1P_PASSPHRASE"; return 0; fi
    local p; read -rsp "$1 gate passphrase: " p >&2; echo >&2; printf '%s' "$p"
}

secret_rt()      { printf '%s' "$(gate_opt "$1" rt "$GATE_RT_BASE/agent-gate/$1")"; }
secret_tokfile() { printf '%s' "$(gate_opt "$1" tokfile token)"; }
secret_blob()    { printf '%s' "$(gate_opt "$1" blob "$GATE_CONF/$1.enc")"; }
secret_magic()   { printf '%s' "$(gate_opt "$1" magic "$(tr '[:lower:]-' '[:upper:]_' <<<"$1")v1:")"; }
secret_label()   { printf '%s' "$(gate_opt "$1" label "$(tr '[:lower:]' '[:upper:]' <<<"$1")")"; }

secret_remaining() { # <name> -> seconds left; rc=1 if locked/expired
    local rt tok exp now e; rt="$(secret_rt "$1")"; tok="$rt/$(secret_tokfile "$1")"; exp="$rt/expiry"
    [[ -s "$tok" && -f "$exp" ]] || return 1
    now=$(date +%s); e=$(cat "$exp" 2>/dev/null || echo 0)
    [[ "$now" -lt "$e" ]] || return 1
    printf '%s' $(( e - now ))
}

_secret_write() { # <name> <secret> <secs> — tmpfs write + expiry + autolock timer
    local name="$1" secret="$2" secs="$3" rt tok
    rt="$(secret_rt "$name")"; tok="$rt/$(secret_tokfile "$name")"
    umask 077; mkdir -p "$rt"
    printf '%s' "$secret" > "$tok"; chmod 600 "$tok"
    echo $(( $(date +%s) + secs )) > "$rt/expiry"; chmod 600 "$rt/expiry"
    systemctl --user stop "agent-gate-lock-$name.timer"           >/dev/null 2>&1
    systemctl --user reset-failed "agent-gate-lock-$name.service" >/dev/null 2>&1
    systemd-run --user --quiet --on-active="$secs" --unit="agent-gate-lock-$name" \
        "$GATE_LIB_DIR/../bin/lock" "$name" >/dev/null 2>&1 \
        || echo "(note: auto-lock timer for $name couldn't be scheduled; expiry is still enforced on use)" >&2
}

_secret_from_ref() { # <name> -> secret on stdout; rc=1 if no ref or unresolvable
    local ref val; ref="$(gate_opt "$1" ref)"; [[ -n "$ref" ]] || return 1
    val="$("$GATE_OP_BIN" read "$ref" 2>/dev/null)" || return 1
    [[ -n "$val" ]] || return 1
    printf '%s' "$val"
}

_secret_from_blob() { # <name> -> secret on stdout; PROMPTS. rc=1 wrong pass / no blob
    local name="$1" blob magic plain
    blob="$(secret_blob "$name")"; magic="$(secret_magic "$name")"
    [[ -f "$blob" ]] || { echo "No enrolled secret for $name at $blob. Enroll with: unlock $name enroll" >&2; return 1; }
    echo "Enter the $(secret_label "$name") gate passphrase:" >&2
    plain="$(GATE_PASS="$(gate_read_pass "$(secret_label "$name")")" openssl enc -d "${GATE_OSSL[@]}" -pass env:GATE_PASS -in "$blob" 2>/dev/null)"
    [[ $? -eq 0 && "$plain" == "$magic"* ]] || { echo "Wrong passphrase or corrupt blob — $name NOT unlocked." >&2; return 1; }
    printf '%s' "${plain#"$magic"}"
}

secret_unlock() { # <name> <timeout-spec>  rc: 0 ok | 1 failed | 2 bad timeout
    local name="$1" spec="$2" secs secret
    secs="$(gate_parse_timeout "$spec")" || return 2
    if secret="$(_secret_from_ref "$name")"; then
        _secret_write "$name" "$secret" "$secs"
        echo "Unlocked $name for $spec (from 1Password). Lock early: lock $name"; return 0
    fi
    [[ -n "$(gate_opt "$name" ref)" ]] && echo "Couldn't reach 1Password for $name — falling back to the passphrase prompt." >&2
    secret="$(_secret_from_blob "$name")" || return 1
    _secret_write "$name" "$secret" "$secs"
    echo "Unlocked $name for $spec (from the enrolled blob). Lock early: lock $name"
}

secret_enroll() { # <name> — secret on stdin (one line) or prompted; passphrase via gate_read_pass
    local name="$1" blob magic secret pass
    blob="$(secret_blob "$name")"; magic="$(secret_magic "$name")"
    if [[ -t 0 ]]; then read -rsp "Paste the $(secret_label "$name") secret (hidden): " secret; echo >&2
    else IFS= read -r secret; fi
    [[ -n "$secret" ]] || { echo "empty secret — aborting" >&2; return 1; }
    pass="$(gate_read_pass "$(secret_label "$name")")"; [[ -n "$pass" ]] || { echo "empty passphrase — aborting" >&2; return 1; }
    umask 077; mkdir -p "$(dirname "$blob")"
    printf '%s%s' "$magic" "$secret" | GATE_PASS="$pass" openssl enc "${GATE_OSSL[@]}" -salt -pass env:GATE_PASS -out "$blob" || return 1
    chmod 600 "$blob"; unset secret pass
    echo "Enrolled $name -> $blob (encrypted, mode 600). Test: unlock $name 15m"
}

secret_lock() { # <name>
    local rt tok; rt="$(secret_rt "$1")"; tok="$rt/$(secret_tokfile "$1")"
    [[ -f "$tok" ]] && { shred -u "$tok" 2>/dev/null || rm -f "$tok"; }
    rm -f "$rt/expiry"
    systemctl --user stop "agent-gate-lock-$1.timer"           >/dev/null 2>&1
    systemctl --user reset-failed "agent-gate-lock-$1.service" >/dev/null 2>&1
    echo "Locked $1."
}

# ---- kind: agent --------------------------------------------------------------
agent_key()  { printf '%s' "$(gate_opt "$1" key  "$GATE_SSH_KEY")"; }
agent_sock() { printf '%s' "$(gate_opt "$1" sock "$GATE_SSH_SOCK")"; }

agent_status() { # <name> -> rc 0 key loaded | 1 agent empty | 2 no agent  (ssh-add -l semantics)
    SSH_AUTH_SOCK="$(agent_sock "$1")" ssh-add -l >/dev/null 2>&1
}

agent_unlock() { # <name> <timeout-spec>  — PROMPTS via ssh-add
    local name="$1" spec="$2" key sock rc
    key="$(agent_key "$name")"; sock="$(agent_sock "$name")"
    [[ -f "$key" ]] || { echo "ERROR: key not found at $key (set GATE_SSH_KEY or key= on the gate)" >&2; return 1; }
    agent_status "$name"; rc=$?
    if [[ $rc -eq 2 ]]; then
        rm -f "$sock"; mkdir -p "$(dirname "$sock")"
        ssh-agent -a "$sock" >/dev/null || { echo "ERROR: couldn't start ssh-agent at $sock" >&2; return 1; }
        echo "Started dedicated ssh-agent at $sock"
    fi
    echo "Loading key (auto-expires in $spec). Enter your passphrase:"
    SSH_AUTH_SOCK="$sock" ssh-add -t "$spec" "$key" || return 1
    echo "Authorized — the agent can use the key for the next $spec.  Lock early with: lock $name"
}

agent_lock() { # <name>
    local sock; sock="$(agent_sock "$1")"
    if [[ -S "$sock" ]]; then
        SSH_AUTH_SOCK="$sock" ssh-add -D >/dev/null 2>&1 || true
        echo "Locked $1 — key removed from the agent."
    else
        echo "Already locked — no dedicated agent for $1."
    fi
}
