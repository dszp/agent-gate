# A time-boxed API token for the agent. Copy to $GATE_DIR/<name>.sh and edit.
#
# Unlock order: `op read <ref>` through GATE_OP_BIN; if that can't resolve, the
# encrypted blob at $GATE_CONF/example.enc is decrypted with a passphrase prompt.
# Write the blob once with:  unlock example enroll
# Consumers read the token from $GATE_RT_BASE/agent-gate/example/token while
# $GATE_RT_BASE/agent-gate/example/expiry is in the future — never from argv.
#
# Optional keys: blob= (path)  magic= (prefix, default EXAMPLEv1:)  rt= (runtime dir)
#                tokfile= (filename inside rt, default token)  label= (prompt text)
gate_register example secret ref='op://Agent-Vault/example-api/credential'
