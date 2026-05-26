#!/usr/bin/env bash
# End-to-end test of qsshd auth, privilege drop, and sudo behaviour.
#
# Spins up a fresh LXD container, installs the locally-built binaries,
# creates a non-sudoer (alice) and a sudoer (bob), and runs the four
# core use cases from the security review:
#
#   1. you can log in as yourself
#   2. you can't log in as someone else unauthorized
#   3. you can't sudo if you are not a sudoer
#   4. you can sudo if you are a sudoer
#
# Requires `lxc` (LXD client) and `cargo` on PATH. The current user must be
# able to talk to lxd (member of the lxd group, or run via sudo).
#
# Env:
#   SQUISH_TEST_IMAGE   lxd image to use (default: ubuntu:22.04)
#   SQUISH_SKIP_BUILD   if non-empty, skip `cargo build` (use existing binaries)

set -euo pipefail

CONTAINER="squish-test-$$"
IMAGE="${SQUISH_TEST_IMAGE:-ubuntu:22.04}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="$(cd "$SCRIPT_DIR/../.." && pwd)"

cleanup() {
  lxc delete --force "$CONTAINER" >/dev/null 2>&1 || true
}
trap cleanup EXIT

log() { printf '[lxd-integration] %s\n' "$*"; }

require() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 2
  }
}

PASS=0
FAIL=0
pass_test() { printf '  \033[32mPASS\033[0m: %s\n' "$*"; PASS=$((PASS + 1)); }
fail_test() { printf '  \033[31mFAIL\033[0m: %s\n' "$*"; FAIL=$((FAIL + 1)); }

require lxc

# --- Build ---
if [[ -z "${SQUISH_SKIP_BUILD:-}" ]]; then
  require cargo
  log "building workspace (release)"
  (cd "$WORKSPACE" && cargo build --release --workspace --quiet)
fi

for bin in qssh qsshd qssh-keygen; do
  if [[ ! -x "$WORKSPACE/target/release/$bin" ]]; then
    echo "missing binary: target/release/$bin (set SQUISH_SKIP_BUILD only when binaries exist)" >&2
    exit 2
  fi
done

# --- Launch container ---
log "launching $IMAGE as $CONTAINER"
lxc launch "$IMAGE" "$CONTAINER" >/dev/null

# Wait for the container to be reachable.
for _ in $(seq 1 30); do
  if lxc exec "$CONTAINER" -- true 2>/dev/null; then
    break
  fi
  sleep 1
done

# --- Install binaries ---
log "installing binaries"
for bin in qssh qsshd qssh-keygen; do
  lxc file push --mode 755 "$WORKSPACE/target/release/$bin" "$CONTAINER/usr/local/bin/$bin"
done

# --- Create users ---
log "creating alice (no sudo) and bob (sudoer NOPASSWD)"
lxc exec "$CONTAINER" -- useradd --create-home --shell /bin/bash alice
lxc exec "$CONTAINER" -- useradd --create-home --shell /bin/bash bob
lxc exec "$CONTAINER" -- bash -c \
  'echo "bob ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/90-bob-test && chmod 440 /etc/sudoers.d/90-bob-test'

# --- Per-user key setup ---
setup_user() {
  local user="$1"
  lxc exec "$CONTAINER" -- runuser -u "$user" -- bash -c '
    set -e
    mkdir -p ~/.config/qssh ~/.squish
    chmod 700 ~/.config/qssh ~/.squish
    qssh-keygen -f ~/.config/qssh/id_ml_dsa_65 > ~/key.pub
    cp ~/key.pub ~/.squish/authorized_keys
    chmod 600 ~/.squish/authorized_keys
  '
}
log "generating keys and ~/.squish/authorized_keys for alice and bob"
setup_user alice
setup_user bob

# --- Start qsshd as root ---
log "starting qsshd on 127.0.0.1:2222"
lxc exec "$CONTAINER" -- mkdir -p /etc/qssh
lxc exec "$CONTAINER" -- bash -c 'cat > /etc/qssh/qsshd.toml <<EOF
bind_addr = "127.0.0.1"
port = 2222
host_key = "/etc/qssh/host.key"
host_cert = "/etc/qssh/host.cert"
EOF'
lxc exec "$CONTAINER" -- bash -c \
  'nohup /usr/local/bin/qsshd --config /etc/qssh/qsshd.toml >/var/log/qsshd.log 2>&1 &'

# Wait for qsshd to bind 2222.
for _ in $(seq 1 40); do
  if lxc exec "$CONTAINER" -- bash -c 'ss -ltn 2>/dev/null | grep -q ":2222 "'; then
    break
  fi
  sleep 0.25
done
if ! lxc exec "$CONTAINER" -- bash -c 'ss -ltn 2>/dev/null | grep -q ":2222 "'; then
  echo "qsshd never bound 2222. Log:" >&2
  lxc exec "$CONTAINER" -- cat /var/log/qsshd.log >&2 || true
  exit 1
fi

# Helper: run COMMAND as USER inside the container.
as_user() {
  local user="$1"
  shift
  lxc exec "$CONTAINER" -- runuser -u "$user" -- bash -c "$*"
}

# --- Tests ---
echo

log "Test 1: alice logs in as alice (whoami must be alice)"
out=$(as_user alice 'qssh -p 2222 alice@127.0.0.1 whoami' 2>&1 || true)
if grep -qx 'alice' <<<"$out"; then
  pass_test "alice -> alice yields whoami=alice"
else
  fail_test "expected 'alice', got: $(printf '%q' "$out")"
fi

log "Test 2: alice cannot log in as bob"
if as_user alice 'qssh -p 2222 bob@127.0.0.1 whoami' >/dev/null 2>&1; then
  fail_test "expected auth failure, but qssh succeeded"
else
  pass_test "alice -> bob denied"
fi

log "Test 3: alice (non-sudoer) cannot sudo"
if as_user alice 'qssh -p 2222 alice@127.0.0.1 sudo -n true' >/dev/null 2>&1; then
  fail_test "alice's sudo unexpectedly succeeded"
else
  pass_test "alice's sudo denied"
fi

log "Test 4: bob (sudoer NOPASSWD) can sudo"
out=$(as_user bob 'qssh -p 2222 bob@127.0.0.1 sudo -n whoami' 2>&1 || true)
if grep -qx 'root' <<<"$out"; then
  pass_test "bob -> root via sudo"
else
  fail_test "expected 'root', got: $(printf '%q' "$out")"
fi

echo
printf '[lxd-integration] %d passed, %d failed\n' "$PASS" "$FAIL"
[[ $FAIL -eq 0 ]]
