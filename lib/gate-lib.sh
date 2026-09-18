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
