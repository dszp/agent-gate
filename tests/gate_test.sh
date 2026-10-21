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

test_config_file_unbound_var_is_safe() {
    setup
    # A config referencing one of the caller's own unset variables must not kill
    # the tool under our `set -u` (item A8): it's sourced with `set +u`.
    printf 'GATE_OWNER="Bob${SOME_VAR_THE_USER_NEVER_SET}"\n' > "$XDG_CONFIG_HOME/agent-gate/config"
    out="$(run_lib 'echo "$GATE_OWNER"' 2>"$TMP/err_cfg")"; rc=$?
    assert_exit "config unbound var rc" "$rc" "0"
    assert_eq "config unbound var owner still loaded" "$out" "Bob"
    assert_eq "config unbound var no stderr" "$(cat "$TMP/err_cfg")" ""
    teardown
}

test_double_source_is_safe() {
    setup
    err="$(bash -c ". '$REPO/lib/gate-lib.sh'; . '$REPO/lib/gate-lib.sh'" 2>&1 1>/dev/null)"
    assert_eq "double-source stderr empty" "$err" ""
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
    out="$(CLAUDE_1P_PASSPHRASE=oldpw run_lib 'echo "$GATE_PASSPHRASE|$GATE_1P_PASSPHRASE"' 2>"$TMP/err_pp")"
    assert_eq "CLAUDE_1P_PASSPHRASE maps to GATE_PASSPHRASE" "$out" "oldpw|oldpw"
    assert_contains "CLAUDE_1P_PASSPHRASE warns" "$(cat "$TMP/err_pp")" "CLAUDE_1P_PASSPHRASE is deprecated, use GATE_PASSPHRASE"
    out="$(GATE_1P_PASSPHRASE=newpw run_lib 'echo "$GATE_PASSPHRASE|$GATE_1P_PASSPHRASE"')"
    assert_eq "GATE_1P_PASSPHRASE alias mirrored onto GATE_PASSPHRASE" "$out" "newpw|newpw"
    teardown
}

test_timeout_parse_and_precedence() {
    setup
    assert_eq "bare secs" "$(run_lib 'gate_parse_timeout 900')" "900"
    assert_eq "minutes"   "$(run_lib 'gate_parse_timeout 15m')" "900"
    assert_eq "hours"     "$(run_lib 'gate_parse_timeout 1h')"  "3600"
    assert_eq "days"      "$(run_lib 'gate_parse_timeout 2d')"  "172800"
    assert_eq "leading zero minutes (base-10, not octal)" "$(run_lib 'gate_parse_timeout 008m')" "480"
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

test_secret_ref_hang_times_out_to_blob() { # an unanswered approval prompt must not block the fallback
    _secret_setup
    stub op 'sleep 30'
    printf 'blobsecret\n' | GATE_1P_PASSPHRASE=pw _run_secret 'secret_enroll tok' >/dev/null 2>&1
    start=$(date +%s)
    out="$(GATE_OP_READ_TIMEOUT=1 GATE_1P_PASSPHRASE=pw _run_secret 'secret_unlock tok 10m' 2>&1)"; rc=$?
    took=$(( $(date +%s) - start ))
    assert_exit "hung ref rc" "$rc" "0"
    [[ $took -lt 10 ]] && PASS=$((PASS+1)) || { FAIL=$((FAIL+1)); echo "FAIL hung ref bounded: took ${took}s"; }
    assert_contains "timeout notice" "$out" "no answer from 1Password for tok in 1s"
    assert_contains "fallback notice" "$out" "falling back to the passphrase"
    assert_eq "token from blob" "$(cat "$XDG_RUNTIME_DIR/agent-gate/tok/token")" "blobsecret"
    out="$(GATE_OP_READ_TIMEOUT=soon _run_secret 'secret_unlock tok 10m' 2>&1)"; rc=$?
    assert_exit "bad read timeout rc" "$rc" "2"
    assert_contains "bad read timeout msg" "$out" "bad timeout 'soon'"
    teardown
}

test_secret_partial_write_scrubs_token() { # token write succeeds, expiry write fails
    _secret_setup
    stub op 'echo "s3cret"'
    rt="$XDG_RUNTIME_DIR/agent-gate/tok"; mkdir -p "$rt/expiry"
    out="$(_run_secret 'secret_unlock tok 15m' 2>"$TMP/err_pw")"; rc=$?
    assert_exit "secret partial write rc" "$rc" "1"
    assert_contains "secret partial write stderr" "$(cat "$TMP/err_pw")" "cannot write"
    [[ -e "$rt/token" ]] && { FAIL=$((FAIL+1)); echo "FAIL secret partial write: token left behind"; } || PASS=$((PASS+1))
    teardown
}

test_secret_write_fails_closed() {
    _secret_setup
    stub op 'echo "s3cret"'
    out="$(GATE_RT_BASE=/proc/nope _run_secret 'secret_unlock tok 15m' 2>"$TMP/err_wf")"; rc=$?
    assert_exit "secret write fails-closed rc" "$rc" "1"
    if [[ "$out" == *"Unlocked"* ]]; then FAIL=$((FAIL+1)); echo "FAIL secret write fails-closed: stdout has Unlocked: [$out]"; else PASS=$((PASS+1)); fi
    assert_contains "secret write fails-closed stderr" "$(cat "$TMP/err_wf")" "cannot write"
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

_agent_setup() { setup; export GATE_BUILTIN_DIR="$REPO/gates.d"; }

test_agent_unlock_starts_agent_when_absent() {
    _agent_setup
    stub ssh-add   'case "$*" in "-l") exit 2;; *) exit 0;; esac'
    stub ssh-agent 'echo "SSH_AGENT_PID=1; export SSH_AGENT_PID;"'
    mkdir -p "$HOME/.ssh"; : > "$HOME/.ssh/agent-gate"
    out="$(run_lib 'gate_load_gates; agent_unlock ssh 1h' 2>&1)"; rc=$?
    assert_exit "agent unlock rc" "$rc" "0"
    assert_contains "agent started" "$(stub_log)" "ssh-agent -a $HOME/.ssh/agent-gate.sock"
    assert_contains "key added with timeout" "$(stub_log)" "ssh-add -t 1h $HOME/.ssh/agent-gate"
    assert_contains "unlock message" "$out" "for the next 1h"
    teardown
}

test_agent_unlock_missing_key() {
    _agent_setup
    stub ssh-add 'exit 0'; stub ssh-agent 'exit 0'
    out="$(run_lib 'gate_load_gates; agent_unlock ssh 1h' 2>&1)"; rc=$?
    assert_exit "missing key rc" "$rc" "1"
    assert_contains "missing key msg" "$out" "key not found"
    teardown
}

test_agent_status_and_lock() {
    _agent_setup
    stub ssh-add 'case "$*" in "-l") exit 1;; *) exit 0;; esac'
    run_lib 'gate_load_gates; agent_status ssh'; assert_exit "status empty agent" "$?" "1"
    mkdir -p "$HOME/.ssh"; python3 -c "import socket,sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])" "$HOME/.ssh/agent-gate.sock"
    out="$(run_lib 'gate_load_gates; agent_lock ssh')"
    assert_contains "lock drops keys" "$(stub_log)" "ssh-add -D"
    assert_contains "lock msg" "$out" "Locked"
    teardown
}

test_gate_ssh_locked_and_unlocked() {
    _agent_setup
    stub ssh-add 'exit 2'; stub ssh 'exit 0'
    printf 'GATE_OWNER=Alice\n' > "$XDG_CONFIG_HOME/agent-gate/config"
    out="$(bash "$REPO/bin/gate-ssh" root@host uptime 2>&1)"; rc=$?
    assert_exit "gate-ssh locked rc" "$rc" "1"
    assert_eq "gate-ssh locked msg" "$out" "LOCKED — no key loaded. Ask Alice to run: unlock ssh [timeout]"
    stub ssh-add 'exit 0'
    bash "$REPO/bin/gate-ssh" root@host uptime >/dev/null 2>&1; assert_exit "gate-ssh unlocked rc" "$?" "0"
    assert_contains "ssh opts" "$(stub_log)" "ssh -F /dev/null -o BatchMode=yes -o IdentitiesOnly=yes -i $HOME/.ssh/agent-gate -o IdentityAgent=$HOME/.ssh/agent-gate.sock -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 root@host uptime"
    ssh_line="$(grep '^ssh ' "$XDG_RUNTIME_DIR/stub.log" | tail -1)"
    case "$ssh_line" in
        "ssh -F /dev/null -o BatchMode=yes"*) PASS=$((PASS+1));;
        *) FAIL=$((FAIL+1)); echo "FAIL ssh argv prefix: [$ssh_line]";;
    esac
    bash "$REPO/bin/gate-ssh" >/dev/null 2>&1; assert_exit "gate-ssh no args rc" "$?" "1"
    teardown
}

test_gate_ssh_missing_key_or_sock() {
    setup
    stub ssh-add 'exit 0'; stub ssh 'exit 0'
    # GATE_SSH_KEY/GATE_SSH_SOCK always default to non-empty via gate_conf_load, so
    # to exercise gate-ssh's own emptiness guard, shadow the built-in ssh gate with
    # a private one whose agent_key/agent_sock legitimately report empty.
    local bdir="$TMP/builtin-empty"; mkdir -p "$bdir"
    cat > "$bdir/ssh.sh" <<'EOF'
agent_key()  { printf ''; }
agent_sock() { printf ''; }
gate_register ssh agent
EOF
    out="$(GATE_BUILTIN_DIR="$bdir" bash "$REPO/bin/gate-ssh" root@host uptime 2>&1)"; rc=$?
    assert_exit "gate-ssh missing key/socket rc" "$rc" "2"
    assert_contains "gate-ssh missing key/socket msg" "$out" "ssh gate has no key/socket configured"
    teardown
}

_disp_setup() {
    setup; export GATE_BUILTIN_DIR="$REPO/gates.d"
    echo 'gate_register tok secret ref=op://V/i/f' > "$XDG_CONFIG_HOME/agent-gate/gates.d/tok.sh"
    stub ssh-add 'exit 2'; stub ssh-agent 'exit 0'; stub op 'echo v'
}
unlock() { bash "$REPO/bin/unlock" "$@"; }
lock()   { bash "$REPO/bin/lock" "$@"; }

test_dispatcher_status_rows() {
    _disp_setup
    out="$(unlock status)"
    assert_contains "ssh row"  "$out" "ssh       LOCKED    unlock ssh [timeout]"
    assert_contains "tok row"  "$out" "tok       LOCKED    unlock tok [timeout]"
    assert_contains "1p row"   "$out" "1p        LOCKED    no profiles enrolled"
    unlock tok 10m >/dev/null 2>&1
    row="$(unlock status | grep '^tok ')"
    assert_contains "tok unlocked state" "$row" "tok       UNLOCKED  ~"
    if [[ "$row" =~ ~(10m\ 00s|9m\ 5[0-9]s)\ left ]]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); echo "FAIL tok remaining: [$row]"; fi
    teardown
}

test_dispatcher_bare_never_unlocks() {
    _disp_setup
    out="$(unlock)"; assert_contains "bare shows usage" "$out" "Usage:"
    assert_file_absent "bare unlock wrote nothing" "$XDG_RUNTIME_DIR/agent-gate/tok/token"
    unlock bogus >/dev/null 2>&1; assert_exit "unknown gate rc" "$?" "2"
    teardown
}

test_dispatcher_unlock_all_order() {
    _disp_setup
    mkdir -p "$HOME/.ssh"; : > "$HOME/.ssh/agent-gate"
    printf 'GATE_1P_PASSPHRASE=pw\n' > "$XDG_CONFIG_HOME/agent-gate/config"
    printf 'Agent-Test\nops_tok\n' | bash "$REPO/bin/1p" enroll acme >/dev/null 2>&1
    # Re-stub `op` (bypassing the harness's generic stub) so its log line records
    # whether the 1p profile's tmpfs token already exists at the moment `op` is
    # called — direct proof that sa unlocks before secret gates read through it.
    cat > "$TMP/bin/op" <<'OPSTUB'
#!/usr/bin/env bash
present=0
[[ -s "$XDG_RUNTIME_DIR/agent-gate/1p/acme/token" ]] && present=1
echo "op $* 1p_token_present=$present" >> "$XDG_RUNTIME_DIR/stub.log"
echo v
OPSTUB
    chmod +x "$TMP/bin/op"
    unlock all 20m >/dev/null 2>&1
    log="$(stub_log)"
    op_line=$(grep -n '^op read' <<<"$log" | head -1 | cut -d: -f1)
    add_line=$(grep -n '^ssh-add -t' <<<"$log" | head -1 | cut -d: -f1)
    [[ -n "$op_line" && -n "$add_line" && "$op_line" -lt "$add_line" ]] && PASS=$((PASS+1)) || { FAIL=$((FAIL+1)); echo "FAIL all order: secret($op_line) before agent($add_line)"; }
    assert_contains "sa (1p) unlocked before secret gate's op read" "$log" "op read op://V/i/f 1p_token_present=1"
    assert_eq "1p unlocked first" "$(cat "$XDG_RUNTIME_DIR/agent-gate/1p/acme/token")" "ops_tok"
    assert_contains "timeout passed to ssh-add" "$log" "ssh-add -t 20m"
    teardown
}

test_dispatcher_lock_all_and_enroll() {
    _disp_setup
    unlock tok 10m >/dev/null 2>&1
    mkdir -p "$HOME/.ssh"; python3 -c "import socket,sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])" "$HOME/.ssh/agent-gate.sock"
    lock >/dev/null 2>&1
    assert_file_absent "lock all scrubbed tok" "$XDG_RUNTIME_DIR/agent-gate/tok/token"
    assert_contains "lock all hit ssh" "$(stub_log)" "ssh-add -D"
    out="$(printf 's\n' | GATE_1P_PASSPHRASE=pw unlock tok enroll 2>&1)"; rc=$?
    assert_exit "enroll via dispatcher rc" "$rc" "0"
    [[ -f "$XDG_CONFIG_HOME/agent-gate/tok.enc" ]] && PASS=$((PASS+1)) || { FAIL=$((FAIL+1)); echo "FAIL enroll blob missing"; }
    unlock ssh enroll >/dev/null 2>&1; assert_exit "enroll on agent kind rc" "$?" "2"
    teardown
}

test_install_seeds_and_never_overwrites() {
    setup
    mkdir -p "$HOME/.local/bin"
    printf 'GATE_OWNER=Keep\n' > "$XDG_CONFIG_HOME/agent-gate/config"
    out="$(bash "$REPO/install.sh" 2>&1)"; rc=$?
    assert_exit "install rc" "$rc" "0"
    for b in unlock lock gate-ssh 1p; do
        assert_eq "symlink $b" "$(readlink -f "$HOME/.local/bin/$b")" "$(readlink -f "$REPO/bin/$b")"
    done
    assert_eq "config untouched" "$(cat "$XDG_CONFIG_HOME/agent-gate/config")" "GATE_OWNER=Keep"
    [[ -d "$XDG_CONFIG_HOME/agent-gate/1p" ]] && PASS=$((PASS+1)) || { FAIL=$((FAIL+1)); echo "FAIL 1p dir"; }
    rm "$XDG_CONFIG_HOME/agent-gate/config"
    bash "$REPO/install.sh" >/dev/null 2>&1
    assert_contains "config seeded from example" "$(cat "$XDG_CONFIG_HOME/agent-gate/config")" "GATE_SSH_KEY"
    teardown
}

test_defaults; test_config_file_overrides; test_config_file_unbound_var_is_safe; test_double_source_is_safe
test_deprecated_env; test_timeout_parse_and_precedence; test_registry
test_secret_unlock_from_ref; test_secret_ref_fails_then_blob; test_secret_ref_hang_times_out_to_blob; test_secret_wrong_passphrase; test_secret_no_ref_no_blob
test_secret_write_fails_closed; test_secret_partial_write_scrubs_token; test_secret_custom_rt_and_lock; test_secret_expired_is_locked
test_agent_unlock_starts_agent_when_absent; test_agent_unlock_missing_key; test_agent_status_and_lock
test_gate_ssh_locked_and_unlocked; test_gate_ssh_missing_key_or_sock
test_dispatcher_status_rows; test_dispatcher_bare_never_unlocks; test_dispatcher_unlock_all_order; test_dispatcher_lock_all_and_enroll
test_install_seeds_and_never_overwrites
report
