#!/usr/bin/env bash
# Shared test harness. Source from a *_test.sh. Dependency-free: every external
# binary the gates touch is replaced by a stub on a temp PATH that logs its argv.
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PASS=0; FAIL=0

setup() {
    TMP="$(mktemp -d)"
    export HOME="$TMP/home" XDG_RUNTIME_DIR="$TMP/run" XDG_CONFIG_HOME="$TMP/home/.config"
    mkdir -p "$HOME" "$XDG_RUNTIME_DIR" "$TMP/bin" "$XDG_CONFIG_HOME/agent-gate/gates.d"
    export PATH="$TMP/bin:$PATH"
    # Unset every knob a developer's shell might carry in.
    unset GATE_SSH_KEY GATE_SSH_SOCK GATE_OP_BIN GATE_DEFAULT_TIMEOUT GATE_OP_READ_TIMEOUT GATE_OWNER \
          GATE_RT_BASE GATE_DIR GATE_1P_RT GATE_PASSPHRASE GATE_1P_PASSPHRASE OP_BIN \
          CLAUDE_UNLOCK_TIMEOUT CLAUDE_1P_TIMEOUT CLAUDE_1P_PASSPHRASE 2>/dev/null
    stub systemd-run 'exit 0'
    stub systemctl   'exit 0'
}
teardown() { rm -rf "$TMP"; }

stub() { # <name> <body>  — body sees $* and may append to $(stub_log)
    printf '#!/usr/bin/env bash\necho "%s $*" >> "%s/stub.log"\n%s\n' "$1" "$XDG_RUNTIME_DIR" "$2" > "$TMP/bin/$1"
    chmod +x "$TMP/bin/$1"
}
stub_log() { cat "$XDG_RUNTIME_DIR/stub.log" 2>/dev/null; }

run_lib() { # <snippet> — run with the lib sourced and config loaded, fresh bash
    bash -c ". '$REPO/lib/gate-lib.sh'; gate_conf_load; $1"
}

assert_eq()       { if [[ "$2" == "$3" ]]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); echo "FAIL $1: expected [$3] got [$2]"; fi; }
assert_contains() { if [[ "$2" == *"$3"* ]]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); echo "FAIL $1: [$2] missing [$3]"; fi; }
assert_not_contains() { if [[ "$2" != *"$3"* ]]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); echo "FAIL $1: [$2] contains [$3]"; fi; }
assert_exit()     { if [[ "$2" == "$3" ]]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); echo "FAIL $1: exit expected $3 got $2"; fi; }
assert_file_absent() { if [[ ! -e "$2" ]]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); echo "FAIL $1: $2 exists"; fi; }

report() { echo "$(basename "$0"): $PASS passed, $FAIL failed"; [[ $FAIL -eq 0 ]]; }
