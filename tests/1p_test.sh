#!/usr/bin/env bash
# Dependency-free harness for bin/1p. Stubs op/systemd on a temp PATH,
# points HOME + XDG_RUNTIME_DIR at temp dirs. Run: bash tests/1p_test.sh
set -uo pipefail
ONEP="${ONEP:-$(cd "$(dirname "$0")/.." && pwd)/bin/1p}"
PASS=0; FAIL=0

setup() {
    TMP="$(mktemp -d)"
    export HOME="$TMP/home"; export XDG_RUNTIME_DIR="$TMP/run"
    export XDG_CONFIG_HOME="$HOME/.config"
    mkdir -p "$HOME" "$XDG_RUNTIME_DIR" "$TMP/bin"
    # Unset every knob a developer's shell might carry in (mirrors harness.sh).
    unset GATE_SSH_KEY GATE_SSH_SOCK GATE_OP_BIN GATE_DEFAULT_TIMEOUT GATE_OP_READ_TIMEOUT GATE_OWNER \
          GATE_RT_BASE GATE_DIR GATE_1P_RT GATE_PASSPHRASE GATE_1P_PASSPHRASE OP_BIN \
          CLAUDE_UNLOCK_TIMEOUT CLAUDE_1P_TIMEOUT CLAUDE_1P_PASSPHRASE 2>/dev/null
    # stub op: log argv + token, answer whoami/read from env/log
    cat > "$TMP/bin/op" <<'OP'
#!/usr/bin/env bash
echo "TOKEN=${OP_SERVICE_ACCOUNT_TOKEN:-} ARGS=$*" >> "$XDG_RUNTIME_DIR/op.log"
case "$1" in
  whoami) echo "op-whoami-ok token=${OP_SERVICE_ACCOUNT_TOKEN:-none}";;
  read)   echo "SECRET_FOR:$2";;
  *)      echo "op-ran:$*";;
esac
OP
    # stubs that must never really schedule/talk to systemd in tests
    printf '#!/usr/bin/env bash\nexit 0\n' > "$TMP/bin/systemd-run"
    printf '#!/usr/bin/env bash\nexit 0\n' > "$TMP/bin/systemctl"
    chmod +x "$TMP/bin/op" "$TMP/bin/systemd-run" "$TMP/bin/systemctl"
    export PATH="$TMP/bin:$PATH"
    export GATE_OP_BIN="$TMP/bin/op"   # 1p reads via $GATE_OP_BIN (real op in prod); tests use the stub
}
teardown() { rm -rf "$TMP"; }

run() { bash "$ONEP" "$@"; }   # captures nothing; caller redirects

assert_eq()      { if [[ "$2" == "$3" ]]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); echo "FAIL $1: expected [$3] got [$2]"; fi; }
assert_contains(){ if [[ "$2" == *"$3"* ]]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); echo "FAIL $1: [$2] missing [$3]"; fi; }
assert_exit()    { if [[ "$2" == "$3" ]]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); echo "FAIL $1: exit expected $3 got $2"; fi; }

test_help() {
    setup
    out="$(run help)"; rc=$?
    assert_exit "help exit" "$rc" "0"
    assert_contains "help text" "$out" "1p unlock"
    assert_contains "help no raw code" "$out" "1p status"
    assert_contains "help includes title line" "$out" "1p — scoped, passphrase-gated, auto-expiring, allowlisted access to 1Password"
    if [[ "$out" == *"set -uo pipefail"* ]]; then FAIL=$((FAIL+1)); echo "FAIL help leaks raw code"; else PASS=$((PASS+1)); fi
    teardown
}

test_status_empty() {
    setup
    out="$(run status)"; rc=$?
    assert_exit "status-empty exit" "$rc" "1"
    assert_contains "status-empty text" "$out" "No profiles enrolled"
    teardown
}

test_parse_timeout_default() {
    setup
    # unlock with no profiles must fail cleanly (exercised more in Task 3)
    out="$(run unlock 2>&1)"; rc=$?
    assert_exit "unlock-no-profiles exit" "$rc" "2"
    assert_contains "unlock-no-profiles text" "$out" "no profiles enrolled"
    teardown
}

test_enroll_writes_encrypted() {
    setup
    printf 'Agent-Test\nops_testtoken123\n' | GATE_1P_PASSPHRASE=pw run enroll acme >/dev/null
    rc=$?
    assert_exit "enroll exit" "$rc" "0"
    assert_eq "enroll file mode" "$(stat -c '%a' "$HOME/.config/agent-gate/1p/acme.enc")" "600"
    # decrypt it back and confirm the blob
    blob="$(GATE_1P_PASSPHRASE=pw openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 \
            -pass env:GATE_1P_PASSPHRASE -in "$HOME/.config/agent-gate/1p/acme.enc")"
    assert_contains "enroll blob tag"   "$blob" "OPSAv2"
    assert_contains "enroll blob vault" "$blob" "vaults=Agent-Test"
    assert_contains "enroll blob token" "$blob" "token=ops_testtoken123"
    teardown
}

test_enroll_rejects_bad_token() {
    setup
    out="$(printf 'Agent-Test\nnot-a-token\n' | GATE_1P_PASSPHRASE=pw run enroll acme 2>&1)"; rc=$?
    assert_exit "enroll bad-token exit" "$rc" "2"
    assert_contains "enroll bad-token text" "$out" "ops_"
    teardown
}

_enroll() { printf '%s\n%s\n' "$1" "$2" | GATE_1P_PASSPHRASE="${3:-pw}" run enroll "$4" >/dev/null; }

test_unlock_writes_tmpfs() {
    setup
    _enroll "Agent-Test" "ops_tok1" pw acme
    out="$(GATE_1P_PASSPHRASE=pw run unlock acme 15m 2>&1)"; rc=$?
    assert_exit "unlock exit" "$rc" "0"
    assert_eq "token present" "$(cat "$XDG_RUNTIME_DIR/agent-gate/1p/acme/token")" "ops_tok1"
    assert_eq "token mode" "$(stat -c '%a' "$XDG_RUNTIME_DIR/agent-gate/1p/acme/token")" "600"
    assert_contains "meta vaults" "$(cat "$XDG_RUNTIME_DIR/agent-gate/1p/acme/meta")" "vaults=Agent-Test"
    # expiry ~ now + 900s
    now=$(date +%s); exp=$(cat "$XDG_RUNTIME_DIR/agent-gate/1p/acme/expiry")
    [[ "$exp" -gt $((now+800)) && "$exp" -lt $((now+1000)) ]] && PASS=$((PASS+1)) || { FAIL=$((FAIL+1)); echo "FAIL expiry window: $exp vs $now"; }
    teardown
}

test_unlock_passphrase_from_fd() { # the dispatcher hands over a passphrase it already read
    setup
    _enroll "Agent-Test" "ops_tok1" pw acme
    out="$(GATE_PASSPHRASE_FD=3 run unlock acme 15m 3<<<"pw" 2>&1 </dev/null)"; rc=$?
    assert_exit "fd unlock exit" "$rc" "0"
    assert_eq "fd token" "$(cat "$XDG_RUNTIME_DIR/agent-gate/1p/acme/token")" "ops_tok1"
    out="$(GATE_PASSPHRASE_FD=x run unlock acme 15m 2>&1 </dev/null)"; rc=$?
    assert_exit "bad fd rejected" "$rc" "2"
    teardown
}

test_unlock_wrong_passphrase() {
    setup
    _enroll "Agent-Test" "ops_tok1" pw acme
    out="$(GATE_1P_PASSPHRASE=WRONG run unlock acme 15m 2>&1)"; rc=$?
    assert_exit "unlock wrong-pass exit" "$rc" "1"
    assert_contains "unlock wrong-pass text" "$out" "NOT unlocked"
    [[ -e "$XDG_RUNTIME_DIR/agent-gate/1p/acme/token" ]] && { FAIL=$((FAIL+1)); echo "FAIL token written on wrong pass"; } || PASS=$((PASS+1))
    teardown
}

test_unlock_partial_write_scrubs_token() { # token write succeeds, expiry write fails
    setup
    _enroll "Agent-Test" "ops_tok1" pw acme
    rt="$XDG_RUNTIME_DIR/agent-gate/1p/acme"; mkdir -p "$rt/expiry"
    out="$(GATE_1P_PASSPHRASE=pw run unlock acme 15m 2>"$TMP/err_pw")"; rc=$?
    assert_exit "unlock partial write exit" "$rc" "1"
    assert_contains "unlock partial write stderr" "$(cat "$TMP/err_pw")" "cannot write"
    [[ -e "$rt/token" ]] && { FAIL=$((FAIL+1)); echo "FAIL unlock partial write: token left behind"; } || PASS=$((PASS+1))
    teardown
}

test_unlock_write_fails_closed() {
    setup
    _enroll "Agent-Test" "ops_tok1" pw acme
    out="$(GATE_1P_RT=/proc/nope GATE_1P_PASSPHRASE=pw run unlock acme 15m 2>"$TMP/err_wf")"; rc=$?
    assert_exit "unlock write fails-closed exit" "$rc" "1"
    if [[ "$out" == *"Unlocked"* ]]; then FAIL=$((FAIL+1)); echo "FAIL unlock write fails-closed: stdout has Unlocked: [$out]"; else PASS=$((PASS+1)); fi
    assert_contains "unlock write fails-closed stderr" "$(cat "$TMP/err_wf")" "cannot write"
    teardown
}

test_unlock_rejects_unknown_arg() {
    setup
    _enroll "Agent-Test" "ops_tok1" pw acme
    out="$(GATE_1P_PASSPHRASE=pw run unlock notaprofile 2>&1)"; rc=$?
    assert_exit "unlock unknown-arg exit" "$rc" "2"
    assert_contains "unlock unknown-arg text" "$out" "'notaprofile' is not an enrolled profile or a timeout (profiles: acme)"
    teardown
}

test_unlock_single_default_profile() {
    setup
    _enroll "Agent-Test" "ops_tok1" pw acme
    GATE_1P_PASSPHRASE=pw run unlock >/dev/null 2>&1; rc=$?
    assert_exit "unlock default-single exit" "$rc" "0"
    assert_eq "default token" "$(cat "$XDG_RUNTIME_DIR/agent-gate/1p/acme/token")" "ops_tok1"
    teardown
}

test_status_unlocked() {
    setup
    _enroll "Agent-Test" "ops_tok1" pw acme
    GATE_1P_PASSPHRASE=pw run unlock acme 15m >/dev/null 2>&1
    out="$(run status)"; rc=$?
    assert_exit "status-unlocked exit" "$rc" "0"
    assert_contains "status-unlocked text" "$out" "UNLOCKED — acme (Agent-Test)"
    teardown
}

test_lock_scrubs() {
    setup
    _enroll "Agent-Test" "ops_tok1" pw acme
    GATE_1P_PASSPHRASE=pw run unlock acme 15m >/dev/null 2>&1
    run lock acme >/dev/null; rc=$?
    assert_exit "lock exit" "$rc" "0"
    [[ -e "$XDG_RUNTIME_DIR/agent-gate/1p/acme/token" ]] && { FAIL=$((FAIL+1)); echo "FAIL token survived lock"; } || PASS=$((PASS+1))
    out="$(run status)"; assert_contains "status after lock" "$out" "LOCKED   — acme"
    teardown
}

test_lock_all() {
    setup
    _enroll "V1" "ops_a" pw acme
    _enroll "V2" "ops_b" pw beta
    GATE_1P_PASSPHRASE=pw run unlock all 15m >/dev/null 2>&1
    run lock >/dev/null
    [[ -e "$XDG_RUNTIME_DIR/agent-gate/1p/acme/token" || -e "$XDG_RUNTIME_DIR/agent-gate/1p/beta/token" ]] \
        && { FAIL=$((FAIL+1)); echo "FAIL lock-all left a token"; } || PASS=$((PASS+1))
    teardown
}

test_read_locked() {
    setup
    _enroll "Agent-Test" "ops_tok1" pw acme
    out="$(run read op://Agent-Test/x/y 2>&1)"; rc=$?
    assert_exit "read-locked exit" "$rc" "3"
    assert_contains "read-locked text" "$out" "LOCKED"
    teardown
}

test_read_injects_token() {
    setup
    _enroll "Agent-Test" "ops_tok1" pw acme
    GATE_1P_PASSPHRASE=pw run unlock acme 15m >/dev/null 2>&1
    out="$(run read op://Agent-Test/db/password)"; rc=$?
    assert_exit "read exit" "$rc" "0"
    assert_contains "read output" "$out" "SECRET_FOR:op://Agent-Test/db/password"
    assert_contains "token injected" "$(cat "$XDG_RUNTIME_DIR/op.log")" "TOKEN=ops_tok1"
    teardown
}

test_blocked_verb() {
    setup
    _enroll "Agent-Test" "ops_tok1" pw acme
    GATE_1P_PASSPHRASE=pw run unlock acme 15m >/dev/null 2>&1
    : > "$XDG_RUNTIME_DIR/op.log"
    # run/signin/vault (dangerous top-level) + bad item/document subverbs are all blocked,
    # exit 2, and must NEVER reach op.
    for bad in "run env" "signin" "vault list" "service-account list" "item bogus" "document bogus" "environment bogus"; do
        out="$(run $bad 2>&1)"; rc=$?
        assert_exit "blocked '$bad' exit" "$rc" "2"
        assert_contains "blocked '$bad' text" "$out" "blocked by 1p gate"
    done
    if [[ -s "$XDG_RUNTIME_DIR/op.log" ]]; then
        FAIL=$((FAIL+1)); echo "FAIL op ran a blocked verb: $(cat "$XDG_RUNTIME_DIR/op.log")"
    else PASS=$((PASS+1)); fi
    teardown
}

test_write_verbs_allowed() {
    setup
    _enroll "Agent-Test" "ops_tok1" pw acme
    GATE_1P_PASSPHRASE=pw run unlock acme 15m >/dev/null 2>&1
    # item/document CRUD + environment read reach op with the token injected (single unlocked profile)
    for v in "item create --category login --title X" "item edit X foo=bar" "item delete X" \
             "document create ./f" "document delete Y" "environment read envid"; do
        : > "$XDG_RUNTIME_DIR/op.log"
        out="$(run $v 2>&1)"; rc=$?
        assert_exit "allowed '$v' exit" "$rc" "0"
        assert_contains "allowed '$v' injected token" "$(cat "$XDG_RUNTIME_DIR/op.log")" "TOKEN=ops_tok1"
    done
    teardown
}

test_item_get_allowed() {
    setup
    _enroll "Agent-Test" "ops_tok1" pw acme
    GATE_1P_PASSPHRASE=pw run unlock acme 15m >/dev/null 2>&1
    out="$(run item list --vault Agent-Test)"; rc=$?
    assert_exit "item-list exit" "$rc" "0"
    assert_contains "item-list ran" "$out" "op-ran:item list"
    teardown
}

test_routing_by_vault() {
    setup
    _enroll "Agent-A" "ops_a" pw acme
    _enroll "Agent-B" "ops_b" pw beta
    GATE_1P_PASSPHRASE=pw run unlock all 15m >/dev/null 2>&1
    : > "$XDG_RUNTIME_DIR/op.log"
    run read op://Agent-B/x/y >/dev/null; rc=$?
    assert_exit "route exit" "$rc" "0"
    assert_contains "routed to B token" "$(cat "$XDG_RUNTIME_DIR/op.log")" "TOKEN=ops_b"
    teardown
}

test_routing_ambiguous_requires_p() {
    setup
    _enroll "Agent-A" "ops_a" pw acme
    _enroll "Agent-B" "ops_b" pw beta
    GATE_1P_PASSPHRASE=pw run unlock all 15m >/dev/null 2>&1
    out="$(run inject 2>&1)"; rc=$?   # vault-less routed verb, 2 unlocked -> must disambiguate
    assert_exit "ambiguous exit" "$rc" "2"
    assert_contains "ambiguous text" "$out" "specify -p"
    # explicit -p resolves it
    out2="$(run -p acme whoami)"; rc2=$?
    assert_exit "forced -p exit" "$rc2" "0"
    assert_contains "forced -p token" "$(cat "$XDG_RUNTIME_DIR/op.log")" "TOKEN=ops_a"
    teardown
}

test_whoami_all_when_multiple() {
    setup
    _enroll "Agent-A" "ops_a" pw acme
    _enroll "Agent-B" "ops_b" pw beta
    GATE_1P_PASSPHRASE=pw run unlock all 15m >/dev/null 2>&1
    out="$(run whoami 2>&1)"; rc=$?   # no -p, 2 unlocked -> show all
    assert_exit "whoami-all exit" "$rc" "0"
    assert_contains "whoami-all header A" "$out" "== acme =="
    assert_contains "whoami-all header B" "$out" "== beta =="
    assert_contains "whoami-all token A" "$(cat "$XDG_RUNTIME_DIR/op.log")" "TOKEN=ops_a"
    assert_contains "whoami-all token B" "$(cat "$XDG_RUNTIME_DIR/op.log")" "TOKEN=ops_b"
    teardown
}

test_lock_shred_fallback() {
    setup
    # stub shred that always fails (simulates missing/broken shred binary)
    printf '#!/usr/bin/env bash\nexit 1\n' > "$TMP/bin/shred"
    chmod +x "$TMP/bin/shred"
    _enroll "Agent-Test" "ops_tok1" pw acme
    GATE_1P_PASSPHRASE=pw run unlock acme 15m >/dev/null 2>&1
    run lock acme >/dev/null; rc=$?
    assert_exit "lock shred-fail exit" "$rc" "0"
    [[ -e "$XDG_RUNTIME_DIR/agent-gate/1p/acme/token" ]] \
        && { FAIL=$((FAIL+1)); echo "FAIL token survived lock when shred fails"; } || PASS=$((PASS+1))
    teardown
}

test_enroll_rejects_invalid_profile_name() {
    setup
    out="$(printf 'Agent-Test\nops_testtoken123\n' | GATE_1P_PASSPHRASE=pw run enroll 'a/b' 2>&1)"; rc=$?
    assert_exit "enroll invalid-profile exit" "$rc" "2"
    assert_contains "enroll invalid-profile text" "$out" "invalid profile"
    shopt -s nullglob
    local -a leaked=("$XDG_CONFIG_HOME/agent-gate/1p"/*.enc)
    shopt -u nullglob
    [[ "${#leaked[@]}" -eq 0 ]] && PASS=$((PASS+1)) || { FAIL=$((FAIL+1)); echo "FAIL enroll invalid-profile created file(s): ${leaked[*]}"; }
    teardown
}

test_force_profile_rejects_traversal() {
    setup
    _enroll "Agent-Test" "ops_tok1" pw acme
    GATE_1P_PASSPHRASE=pw run unlock acme 15m >/dev/null 2>&1
    out="$(run -p '../x' whoami 2>&1)"; rc=$?
    assert_exit "force traversal exit" "$rc" "2"
    assert_contains "force traversal text" "$out" "invalid profile"
    teardown
}

test_internal_token_unlocked() {
    setup
    _enroll "Agent-Test" "ops_tok1" pw acme
    GATE_1P_PASSPHRASE=pw run unlock acme 15m >/dev/null 2>&1
    out="$(run internal-token acme)"; rc=$?
    assert_exit "internal-token unlocked exit" "$rc" "0"
    assert_eq "internal-token value" "$out" "ops_tok1"
    teardown
}
test_internal_token_locked() {
    setup
    _enroll "Agent-Test" "ops_tok1" pw acme
    out="$(run internal-token acme 2>&1)"; rc=$?
    assert_exit "internal-token locked exit" "$rc" "3"
    [[ -z "$out" || "$out" != *ops_* ]] && PASS=$((PASS+1)) || { FAIL=$((FAIL+1)); echo "FAIL internal-token leaked while locked"; }
    teardown
}

test_profiles_lists_enrolled() {
    setup
    _enroll "Agent-A" "ops_a" pw acme
    _enroll "Agent-B" "ops_b" pw beta
    out="$(run _profiles)"; rc=$?
    assert_exit "_profiles exit" "$rc" "0"
    assert_contains "_profiles has acme" "$out" "acme"
    assert_contains "_profiles has beta" "$out" "beta"
    teardown
}

test_vaults_unlocked() {
    setup
    _enroll "Agent-Test" "ops_tok1" pw acme
    GATE_1P_PASSPHRASE=pw run unlock acme 15m >/dev/null 2>&1
    out="$(run _vaults acme)"; rc=$?
    assert_exit "_vaults unlocked exit" "$rc" "0"
    assert_eq "_vaults value" "$out" "Agent-Test"
    teardown
}
test_vaults_locked() {
    setup
    _enroll "Agent-Test" "ops_tok1" pw acme
    out="$(run _vaults acme 2>&1)"; rc=$?
    assert_exit "_vaults locked exit" "$rc" "1"
    assert_eq "_vaults locked empty stdout" "$out" ""
    teardown
}

test_unlock_all_by_default() {
    setup
    _enroll "Agent-A" "ops_a" pw acme
    _enroll "Agent-B" "ops_b" pw beta
    out="$(GATE_1P_PASSPHRASE=pw run unlock 15m 2>&1)"; rc=$?
    assert_exit "bare-unlock-all exit" "$rc" "0"
    assert_eq "bare-unlock A token" "$(cat "$XDG_RUNTIME_DIR/agent-gate/1p/acme/token" 2>/dev/null)" "ops_a"
    assert_eq "bare-unlock B token" "$(cat "$XDG_RUNTIME_DIR/agent-gate/1p/beta/token" 2>/dev/null)" "ops_b"
    teardown
}

test_help; test_status_empty; test_parse_timeout_default
test_enroll_writes_encrypted; test_enroll_rejects_bad_token
test_unlock_writes_tmpfs; test_unlock_wrong_passphrase; test_unlock_write_fails_closed; test_unlock_partial_write_scrubs_token; test_unlock_rejects_unknown_arg
test_unlock_single_default_profile
test_status_unlocked; test_lock_scrubs; test_lock_all
test_read_locked; test_read_injects_token; test_blocked_verb; test_item_get_allowed
test_routing_by_vault; test_routing_ambiguous_requires_p; test_write_verbs_allowed
test_lock_shred_fallback; test_enroll_rejects_invalid_profile_name; test_force_profile_rejects_traversal
test_unlock_passphrase_from_fd; test_unlock_all_by_default; test_whoami_all_when_multiple
test_internal_token_unlocked; test_internal_token_locked
test_profiles_lists_enrolled
test_vaults_unlocked; test_vaults_locked
echo "-----"; echo "PASS=$PASS FAIL=$FAIL"; [[ "$FAIL" -eq 0 ]]
