#!/usr/bin/env bash
. "$(dirname "$0")/harness.sh"

test_defaults() {
    setup
    out="$(run_lib 'echo "$GATE_CONF|$GATE_SSH_KEY|$GATE_OP_BIN|$GATE_DEFAULT_TIMEOUT|$GATE_OWNER|$GATE_RT_BASE|$GATE_DIR|$GATE_1P_RT"')"
    assert_eq "conf dir"     "$(cut -d'|' -f1 <<<"$out")" "$XDG_CONFIG_HOME/agent-gate"
    assert_eq "ssh key"      "$(cut -d'|' -f2 <<<"$out")" "$HOME/.ssh/agent-gate"
    assert_eq "op bin"       "$(cut -d'|' -f3 <<<"$out")" "op"
    assert_eq "timeout"      "$(cut -d'|' -f4 <<<"$out")" "30m"
    assert_eq "owner"        "$(cut -d'|' -f5 <<<"$out")" "the owner"
    assert_eq "rt base"      "$(cut -d'|' -f6 <<<"$out")" "$XDG_RUNTIME_DIR"
    assert_eq "gate dir"     "$(cut -d'|' -f7 <<<"$out")" "$XDG_CONFIG_HOME/agent-gate/gates.d"
    assert_eq "1p rt"        "$(cut -d'|' -f8 <<<"$out")" "$XDG_RUNTIME_DIR/agent-gate/1p"
    teardown
}

test_config_file_overrides() {
    setup
    printf 'GATE_OWNER=Alice\nGATE_OP_BIN=/opt/op\n' > "$XDG_CONFIG_HOME/agent-gate/config"
    out="$(run_lib 'echo "$GATE_OWNER|$GATE_OP_BIN"')"
    assert_eq "owner from config" "${out%%|*}" "Alice"
    assert_eq "op from config"    "${out##*|}" "/opt/op"
    teardown
}

test_deprecated_env() {
    setup
    out="$(OP_BIN=/legacy/op run_lib 'echo "$GATE_OP_BIN"' 2>"$TMP/err")"
    assert_eq "OP_BIN honored" "$out" "/legacy/op"
    assert_contains "OP_BIN warns" "$(cat "$TMP/err")" "OP_BIN is deprecated"
    out="$(CLAUDE_UNLOCK_TIMEOUT=2h run_lib 'gate_register ssh agent; gate_timeout_for ssh' 2>"$TMP/err")"
    assert_eq "CLAUDE_UNLOCK_TIMEOUT honored for ssh" "$out" "2h"
    assert_contains "CLAUDE_UNLOCK_TIMEOUT warns" "$(cat "$TMP/err")" "CLAUDE_UNLOCK_TIMEOUT is deprecated"
    out="$(CLAUDE_FOO_TIMEOUT=45m run_lib 'gate_register foo secret; gate_timeout_for foo' 2>/dev/null)"
    assert_eq "CLAUDE_<NAME>_TIMEOUT honored" "$out" "45m"
    teardown
}

test_timeout_parse_and_precedence() {
    setup
    assert_eq "bare secs" "$(run_lib 'gate_parse_timeout 900')" "900"
    assert_eq "minutes"   "$(run_lib 'gate_parse_timeout 15m')" "900"
    assert_eq "hours"     "$(run_lib 'gate_parse_timeout 1h')"  "3600"
    assert_eq "days"      "$(run_lib 'gate_parse_timeout 2d')"  "172800"
    run_lib 'gate_parse_timeout nope' >/dev/null 2>&1; assert_exit "bad timeout rc" "$?" "2"
    run_lib 'gate_parse_timeout 0'    >/dev/null 2>&1; assert_exit "zero timeout rc" "$?" "2"
    assert_eq "arg wins"  "$(GATE_FOO_TIMEOUT=1h run_lib 'gate_register foo secret; gate_timeout_for foo 5m')" "5m"
    assert_eq "env wins"  "$(GATE_FOO_TIMEOUT=1h run_lib 'gate_register foo secret; gate_timeout_for foo')"    "1h"
    assert_eq "default"   "$(run_lib 'gate_register foo secret; gate_timeout_for foo')" "30m"
    assert_eq "fmt hours" "$(run_lib 'gate_fmt_remaining 3840')" "1h 04m"
    assert_eq "fmt mins"  "$(run_lib 'gate_fmt_remaining 750')"  "12m 30s"
    teardown
}

test_registry() {
    setup
    out="$(run_lib 'gate_register a secret ref=op://V/i/f tokfile=tok; gate_register b agent; echo "${GATE_NAMES[*]}|$(gate_kind a)|$(gate_opt a ref)|$(gate_opt a tokfile)|$(gate_opt a missing dflt)"')"
    assert_eq "registry" "$out" "a b|secret|op://V/i/f|tok|dflt"
    run_lib 'gate_register a secret; gate_register a secret' >/dev/null 2>&1; assert_exit "duplicate name rc" "$?" "2"
    run_lib 'gate_register a bogus' >/dev/null 2>&1; assert_exit "unknown kind rc" "$?" "2"
    # drop-in discovery: builtin dir then $GATE_DIR, sorted
    mkdir -p "$TMP/builtin"
    echo 'gate_register zz agent'  > "$TMP/builtin/zz.sh"
    echo 'gate_register mm secret' > "$XDG_CONFIG_HOME/agent-gate/gates.d/mm.sh"
    echo 'gate_register aa secret' > "$XDG_CONFIG_HOME/agent-gate/gates.d/aa.sh"
    out="$(GATE_BUILTIN_DIR="$TMP/builtin" run_lib 'gate_load_gates; echo "${GATE_NAMES[*]}"')"
    assert_eq "load order" "$out" "zz aa mm"
    echo 'gate_register zz secret' > "$XDG_CONFIG_HOME/agent-gate/gates.d/zz.sh"
    GATE_BUILTIN_DIR="$TMP/builtin" run_lib 'gate_load_gates' >/dev/null 2>&1; assert_exit "drop-in shadowing builtin rc" "$?" "2"
    teardown
}

test_defaults; test_config_file_overrides; test_deprecated_env; test_timeout_parse_and_precedence; test_registry
report
