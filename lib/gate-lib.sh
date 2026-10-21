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
GATE_ROOT="$(cd "$GATE_LIB_DIR/.." && pwd)"
: "${GATE_BUILTIN_DIR:=$GATE_LIB_DIR/../gates.d}"

gate_die()  { echo "$*" >&2; exit 2; }

declare -A _GATE_WARNED=()
gate_warn_deprecated() { # <old> <new> — one note per name per process
    [[ -n "${_GATE_WARNED[$1]:-}" ]] && return 0
    _GATE_WARNED[$1]=1
    echo "agent-gate: $1 is deprecated, use $2" >&2
}

# ---- deprecated-name mapping — ONE place. Delete this function and its three
# call sites (below, and in gate_timeout_for) when the legacy names are retired.
gate_legacy_env() { # <new> <old>... -> value of <new>, else first-set <old> (warns once); rc=1 if none set
    local new="$1"; shift
    [[ -n "${!new:-}" ]] && { printf '%s' "${!new}"; return 0; }
    local old
    for old in "$@"; do
        if [[ -n "${!old:-}" ]]; then
            gate_warn_deprecated "$old" "$new"
            printf '%s' "${!old}"
            return 0
        fi
    done
    return 1
}

# ---- config -------------------------------------------------------------------
gate_conf_load() {
    GATE_CONF="${XDG_CONFIG_HOME:-$HOME/.config}/agent-gate"
    # shellcheck source=/dev/null
    # A user's config may reference an unbound variable of their own; don't let
    # that kill the tool under our own `set -u`.
    if [[ -f "$GATE_CONF/config" ]]; then set +u; . "$GATE_CONF/config"; set -u; fi
    GATE_OP_BIN="$(gate_legacy_env GATE_OP_BIN OP_BIN)" || true
    GATE_PASSPHRASE="$(gate_legacy_env GATE_PASSPHRASE CLAUDE_1P_PASSPHRASE)" || true
    : "${GATE_SSH_KEY:=$HOME/.ssh/agent-gate}"
    : "${GATE_SSH_SOCK:=$HOME/.ssh/agent-gate.sock}"
    : "${GATE_OP_BIN:=op}"
    : "${GATE_DEFAULT_TIMEOUT:=30m}"
    : "${GATE_OP_READ_TIMEOUT:=45s}"
    : "${GATE_OWNER:=the owner}"
    : "${GATE_RT_BASE:=${XDG_RUNTIME_DIR:-/run/user/$(id -u)}}"
    : "${GATE_DIR:=$GATE_CONF/gates.d}"
    : "${GATE_1P_RT:=$GATE_RT_BASE/agent-gate/1p}"
    export GATE_CONF GATE_SSH_KEY GATE_SSH_SOCK GATE_OP_BIN GATE_DEFAULT_TIMEOUT \
           GATE_OP_READ_TIMEOUT GATE_OWNER GATE_RT_BASE GATE_DIR GATE_1P_RT
    # GATE_PASSPHRASE and its alias GATE_1P_PASSPHRASE must agree: whichever the
    # caller set, mirror it onto the other so bin/1p and this lib see the same value.
    if [[ -n "${GATE_PASSPHRASE:-}" || -n "${GATE_1P_PASSPHRASE:-}" ]]; then
        : "${GATE_PASSPHRASE:=${GATE_1P_PASSPHRASE:-}}"
        : "${GATE_1P_PASSPHRASE:=${GATE_PASSPHRASE:-}}"
        export GATE_PASSPHRASE GATE_1P_PASSPHRASE
    fi
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
    # 10#$n: force base-10 so a leading zero (008m) isn't parsed as invalid octal.
    case "$unit" in
        w) secs=$((10#$n*604800));;
        d) secs=$((10#$n*86400));;
        h) secs=$((10#$n*3600));;
        m) secs=$((10#$n*60));;
        *) secs=$((10#$n));;
    esac
    [[ "$secs" -gt 0 ]] || { echo "agent-gate: timeout must be > 0 (got '$t')" >&2; return 2; }
    printf '%s' "$secs"
}

gate_timeout_for() { # <name> [explicit] -> effective spec. arg > GATE_<NAME>_TIMEOUT > default
    local name="$1" explicit="${2:-}" up var val
    [[ -n "$explicit" ]] && { printf '%s' "$explicit"; return 0; }
    up="$(tr '[:lower:]-' '[:upper:]_' <<<"$name")"; var="GATE_${up}_TIMEOUT"
    if [[ "$name" == ssh ]]; then
        val="$(gate_legacy_env "$var" "CLAUDE_${up}_TIMEOUT" CLAUDE_UNLOCK_TIMEOUT)" && { printf '%s' "$val"; return 0; }
    else
        val="$(gate_legacy_env "$var" "CLAUDE_${up}_TIMEOUT")" && { printf '%s' "$val"; return 0; }
    fi
    printf '%s' "$GATE_DEFAULT_TIMEOUT"
}

gate_fmt_remaining() { # <seconds> -> "1h 04m" / "12m 30s"
    local s="$1"
    if [[ "$s" -ge 3600 ]]; then printf '%dh %02dm' $(( s / 3600 )) $(( (s % 3600) / 60 ))
    else printf '%dm %02ds' $(( s / 60 )) $(( s % 60 )); fi
}

# ---- kind: secret -------------------------------------------------------------
[[ -v GATE_OSSL ]] || readonly GATE_OSSL=(-aes-256-cbc -pbkdf2 -iter 600000)

gate_read_pass() { # <label> -> passphrase on stdout. GATE_PASSPHRASE (alias GATE_1P_PASSPHRASE) is the automation/test hook.
    if [[ -n "${GATE_PASSPHRASE:-}" ]]; then printf '%s' "$GATE_PASSPHRASE"; return 0; fi
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

gate_warn_not_memory() { # <dir> — stderr warning (never a failure) when plaintext landed on real disk
    case "$(stat -f -c %T "$1" 2>/dev/null)" in
        tmpfs|ramfs) ;;
        *) echo "agent-gate: warning: $1 is not memory-backed; the token will survive a reboot" >&2 ;;
    esac
}

_secret_write() { # <name> <secret> <secs> — tmpfs write + expiry + autolock timer; rc=1 on write failure (fail closed)
    local name="$1" secret="$2" secs="$3" rt tok
    rt="$(secret_rt "$name")"; tok="$rt/$(secret_tokfile "$name")"
    umask 077
    if ! mkdir -p "$rt" || ! printf '%s' "$secret" > "$tok" || ! echo $(( $(date +%s) + secs )) > "$rt/expiry"; then
        # a token with no expiry beside it is plaintext nothing will ever scrub
        secret_lock "$name" >/dev/null 2>&1
        echo "agent-gate: cannot write $rt (is GATE_RT_BASE writable?)" >&2
        return 1
    fi
    chmod 600 "$tok" "$rt/expiry"
    gate_warn_not_memory "$rt"
    systemctl --user stop "agent-gate-lock-$name.timer"           >/dev/null 2>&1
    systemctl --user reset-failed "agent-gate-lock-$name.service" >/dev/null 2>&1
    systemd-run --user --quiet --on-active="$secs" --unit="agent-gate-lock-$name" \
        "$GATE_ROOT/bin/lock" "$name" >/dev/null 2>&1 \
        || echo "(note: auto-lock timer for $name couldn't be scheduled; expiry is still enforced on use)" >&2
}

# Bounded by GATE_OP_READ_TIMEOUT: a GATE_OP_BIN that asks for approval (a TouchID
# proxy, a desktop-app prompt) blocks until someone answers, and an unanswered
# prompt neither succeeds nor fails — so without a bound the blob fallback in
# secret_unlock could never fire. The 45s default leaves room to approve. `timeout`
# signals its whole process group, so a child holding the pipe dies too and the
# command substitution can't hang on an inherited stdout.
_secret_from_ref() { # <name> <read-secs> -> secret on stdout; rc=1 if no ref or unresolvable
    local ref val rc; ref="$(gate_opt "$1" ref)"; [[ -n "$ref" ]] || return 1
    val="$(timeout -k 5 "$2" "$GATE_OP_BIN" read "$ref" 2>/dev/null)"; rc=$?
    if [[ $rc -eq 124 || $rc -eq 137 ]]; then
        echo "agent-gate: no answer from 1Password for $1 in ${2}s (unapproved prompt?)." >&2
        return 1
    fi
    [[ $rc -eq 0 ]] || return 1
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
    local name="$1" spec="$2" secs read_secs secret
    secs="$(gate_parse_timeout "$spec")" || return 2
    read_secs="$(gate_parse_timeout "$GATE_OP_READ_TIMEOUT")" || return 2
    if secret="$(_secret_from_ref "$name" "$read_secs")"; then
        _secret_write "$name" "$secret" "$secs" || return 1
        echo "Unlocked $name for $spec (from 1Password). Lock early: lock $name"; return 0
    fi
    [[ -n "$(gate_opt "$name" ref)" ]] && echo "Couldn't reach 1Password for $name — falling back to the passphrase prompt." >&2
    secret="$(_secret_from_blob "$name")" || return 1
    _secret_write "$name" "$secret" "$secs" || return 1
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

# ---- kind: sa -----------------------------------------------------------------
# 1p owns multi-profile state; the dispatcher delegates rather than duplicating it.
sa_bin()    { printf '%s' "$GATE_ROOT/bin/1p"; }
sa_status() { "$(sa_bin)" status 2>/dev/null; }
sa_unlock() { shift; "$(sa_bin)" unlock "$@"; }   # <name> [profile] [timeout]
sa_lock()   { "$(sa_bin)" lock; }
