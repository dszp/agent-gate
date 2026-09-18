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
    run_lib 'gate_parse_timeout abcs' 2>"$TMP/err_abcs"; assert_exit "abcs rc" "$?" "2"; assert_contains "abcs stderr" "$(cat "$TMP/err_abcs")" "bad timeout"
    run_lib 'gate_parse_timeout 5xm' 2>"$TMP/err_5xm"; assert_exit "5xm rc" "$?" "2"
    run_lib 'gate_parse_timeout nope' 2>"$TMP/err_nope"; assert_contains "nope stderr" "$(cat "$TMP/err_nope")" "bad timeout"
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

_secret_setup() { # registers gate "tok" with ref + default blob; stubs op + openssl passthrough
    setup
    echo 'gate_register tok secret ref=op://V/item/field' > "$XDG_CONFIG_HOME/agent-gate/gates.d/tok.sh"
    export GATE_BUILTIN_DIR="$TMP/nobuiltins"; mkdir -p "$GATE_BUILTIN_DIR"
}
_run_secret() { run_lib "gate_load_gates; $1"; }

test_secret_unlock_from_ref() {
    _secret_setup
    stub op 'echo "s3cret"'
    out="$(_run_secret 'secret_unlock tok 15m' 2>&1)"; rc=$?
    assert_exit "ref unlock rc" "$rc" "0"
    rt="$XDG_RUNTIME_DIR/agent-gate/tok"
    assert_eq "token written" "$(cat "$rt/token")" "s3cret"
    assert_eq "token mode" "$(stat -c '%a' "$rt/token")" "600"
    now=$(date +%s); exp=$(cat "$rt/expiry")
    [[ $((exp-now)) -ge 895 && $((exp-now)) -le 905 ]] && PASS=$((PASS+1)) || { FAIL=$((FAIL+1)); echo "FAIL expiry ~900s: $((exp-now))"; }
    assert_contains "op called with ref" "$(stub_log)" "op read op://V/item/field"
    assert_contains "autolock scheduled" "$(stub_log)" "systemd-run --user --quiet --on-active=900 --unit=agent-gate-lock-tok"
    assert_eq "remaining rc" "$(_run_secret 'secret_remaining tok >/dev/null && echo up || echo down')" "up"
    teardown
}

test_secret_ref_fails_then_blob() {
    _secret_setup
    stub op 'exit 1'
    # enroll a blob non-interactively: secret on stdin, passphrase via hook
    out="$(printf 'blobsecret\n' | GATE_1P_PASSPHRASE=pw _run_secret 'secret_enroll tok' 2>&1)"; rc=$?
    assert_exit "enroll rc" "$rc" "0"
    blob="$XDG_CONFIG_HOME/agent-gate/tok.enc"
    assert_eq "blob mode" "$(stat -c '%a' "$blob")" "600"
    plain="$(GATE_1P_PASSPHRASE=pw openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -pass env:GATE_1P_PASSPHRASE -in "$blob")"
    assert_eq "blob = magic+secret" "$plain" "TOKv1:blobsecret"
    out="$(GATE_1P_PASSPHRASE=pw _run_secret 'secret_unlock tok 10m' 2>&1)"; rc=$?
    assert_exit "blob unlock rc" "$rc" "0"
    assert_contains "fallback notice" "$out" "falling back to the passphrase"
    assert_eq "token from blob" "$(cat "$XDG_RUNTIME_DIR/agent-gate/tok/token")" "blobsecret"
    teardown
}

test_secret_wrong_passphrase() {
    _secret_setup
    stub op 'exit 1'
    printf 'blobsecret\n' | GATE_1P_PASSPHRASE=pw _run_secret 'secret_enroll tok' >/dev/null 2>&1
    out="$(GATE_1P_PASSPHRASE=WRONG _run_secret 'secret_unlock tok 10m' 2>&1)"; rc=$?
    assert_exit "wrong pass rc" "$rc" "1"
    assert_contains "wrong pass msg" "$out" "NOT unlocked"
    assert_file_absent "no token on wrong pass" "$XDG_RUNTIME_DIR/agent-gate/tok/token"
    assert_file_absent "no expiry on wrong pass" "$XDG_RUNTIME_DIR/agent-gate/tok/expiry"
    teardown
}

test_secret_no_ref_no_blob() {
    _secret_setup
    stub op 'exit 1'
    out="$(_run_secret 'secret_unlock tok 10m' 2>&1)"; rc=$?
    assert_exit "nothing enrolled rc" "$rc" "1"
    assert_contains "enroll hint" "$out" "unlock tok enroll"
    teardown
}

test_secret_custom_rt_and_lock() {
    _secret_setup
    echo 'gate_register tok secret ref=op://V/i/f rt=$GATE_RT_BASE/legacy-dir tokfile=vaultpw' > "$XDG_CONFIG_HOME/agent-gate/gates.d/tok.sh"
    stub op 'echo v'
    _run_secret 'secret_unlock tok 5m' >/dev/null 2>&1
    assert_eq "custom tokfile" "$(cat "$XDG_RUNTIME_DIR/legacy-dir/vaultpw")" "v"
    _run_secret 'secret_lock tok' >/dev/null 2>&1
    assert_file_absent "lock removes token" "$XDG_RUNTIME_DIR/legacy-dir/vaultpw"
    assert_file_absent "lock removes expiry" "$XDG_RUNTIME_DIR/legacy-dir/expiry"
    assert_contains "lock stops timer" "$(stub_log)" "systemctl --user stop agent-gate-lock-tok.timer"
    teardown
}

test_secret_expired_is_locked() {
    _secret_setup
    rt="$XDG_RUNTIME_DIR/agent-gate/tok"; mkdir -p "$rt"; echo x > "$rt/token"; echo 1 > "$rt/expiry"
    _run_secret 'secret_remaining tok' >/dev/null; assert_exit "expired rc" "$?" "1"
    teardown
}

test_defaults; test_config_file_overrides; test_deprecated_env; test_timeout_parse_and_precedence; test_registry
test_secret_unlock_from_ref; test_secret_ref_fails_then_blob; test_secret_wrong_passphrase; test_secret_no_ref_no_blob; test_secret_custom_rt_and_lock; test_secret_expired_is_locked
report
