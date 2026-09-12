#!/usr/bin/env bash
#
# Provision a writable software PKCS#11 token and run the integration suite
# against it.
#
# The suite needs a token that will create keys. SoftHSM is the usual answer and
# is not installable on the primary dev host (no package, no network egress), so
# this uses NSS softoken instead: it ships with the `nss` package, which is
# already present because Firefox and curl depend on it, and it is a full
# software token — EC key generation, ECDSA, AES-GCM, persistent objects.
#
# Two things about it are not obvious and are the reason this script exists:
#
#   * With `CK_C_INITIALIZE_ARGS.pReserved` left null, softoken offers only
#     write-protected slots, so key creation fails and every tier-two test
#     skips. The database is named by a configuration string passed through
#     that field, which is what ZCRYPTO_PKCS11_CONFIG carries.
#
#   * A freshly created database has no user PIN, and softoken answers
#     CKR_PIN_EXPIRED to a login until one is set. `certutil -N -f` sets it at
#     creation time.
#
# Slot index 1 is the "NSS Certificate DB" token, the one backed by the
# database directory. Index 0 is "NSS Generic Crypto Services", which is
# write-protected regardless of configuration.
#
# Each invocation gets its own database directory under a parent, removed on
# exit along with the generated PIN. The parent is never deleted: an earlier
# version recursively deleted a caller-overridable path at startup, so two
# concurrent runs erased each other's live token -- and it left both the
# database and the PIN file behind afterwards. Set ZCRYPTO_KEEP_STATE=1 to
# retain the directory for inspection; the path is printed. Note that retaining
# it retains the PIN file with it.
#
# ZCRYPTO_PKCS11_DB_ROOT names the *parent*. The previous ZCRYPTO_PKCS11_DB
# named the database directory itself and was deleted, so the rename makes a
# stale setting inert instead of silently changing meaning.

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
zig_bin="${ZIG:-/opt/zig-dev/zig}"
module="${ZCRYPTO_PKCS11_MODULE:-/usr/lib/libsoftokn3.so}"
db_root="${ZCRYPTO_PKCS11_DB_ROOT:-$repo_root/.scratch/pkcs11-softoken}"

# Generated per run rather than defaulted to a literal, so no PIN is committed
# and a stale database cannot be unlocked by reading this script. It guards a
# throwaway token holding only keys this suite creates and destroys.
pin="${ZCRYPTO_PKCS11_PIN:-$(head -c 18 /dev/urandom | base64)}"

cd "$repo_root"

if [ ! -e "$module" ]; then
    echo "PKCS#11 module not found: $module" >&2
    echo "Install the 'nss' package, or set ZCRYPTO_PKCS11_MODULE to another provider." >&2
    exit 1
fi

if ! command -v certutil >/dev/null 2>&1; then
    echo "certutil not found; it ships with the same 'nss' package as $module." >&2
    exit 1
fi

# Only the parent is created. It is never removed, because it is a location the
# caller chose and may hold other runs' retained evidence.
mkdir -p "$db_root"

# mktemp creates the directory 0700 at creation rather than widening a default
# and narrowing it afterwards, and it makes the name unique against concurrent
# invocations without this script implementing its own collision handling.
db_dir="$(mktemp -d -p "$db_root" "run-XXXXXXXX")"

cleanup() {
    if [ "${ZCRYPTO_KEEP_STATE:-0}" = "1" ]; then
        echo "softoken database retained at $db_dir (contains the generated PIN)" >&2
    else
        rm -rf "$db_dir"
    fi
}
# Signals exit rather than cleaning up directly, so cleanup runs once from the
# EXIT trap on every path instead of twice on an interrupt.
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP

pin_file="$db_dir/pin"
# Written inside a subshell umask rather than chmod'd afterwards, so the PIN
# never exists at the caller's default mode even momentarily.
(umask 077 && printf '%s' "$pin" > "$pin_file")

certutil -N -d "sql:$db_dir" -f "$pin_file"

: "${ZIG_GLOBAL_CACHE_DIR:=$repo_root/.scratch/zig-global-cache}"
: "${ZIG_LOCAL_CACHE_DIR:=$repo_root/.scratch/pkcs11-cache}"
export ZIG_GLOBAL_CACHE_DIR ZIG_LOCAL_CACHE_DIR
mkdir -p "$ZIG_GLOBAL_CACHE_DIR" "$ZIG_LOCAL_CACHE_DIR"

export ZCRYPTO_PKCS11_MODULE="$module"
export ZCRYPTO_PKCS11_CONFIG="configdir='sql:$db_dir' certPrefix='' keyPrefix='' secmod='' flags="
export ZCRYPTO_PKCS11_PIN="$pin"
export ZCRYPTO_PKCS11_SLOT="${ZCRYPTO_PKCS11_SLOT:-1}"

"$zig_bin" build pkcs11-integration -Dpkcs11=true --summary all

# Also exercise the read-only path, which reaches the branches a writable token
# never takes: a token that refuses object creation. p11-kit-trust is present
# wherever p11-kit is, and softoken with no configuration string is the other.
#
# The configuration string and PIN must be cleared, not just the module path:
# leaving them set is what makes softoken hand back the writable token again,
# and the run would silently repeat the tier-two pass instead of covering the
# read-only branches it is here for.
if [ -e /usr/lib/pkcs11/p11-kit-trust.so ]; then
    env -u ZCRYPTO_PKCS11_CONFIG -u ZCRYPTO_PKCS11_PIN -u ZCRYPTO_PKCS11_SLOT \
        ZCRYPTO_PKCS11_MODULE=/usr/lib/pkcs11/p11-kit-trust.so \
        "$zig_bin" build pkcs11-integration -Dpkcs11=true --summary all
fi

env -u ZCRYPTO_PKCS11_CONFIG -u ZCRYPTO_PKCS11_PIN -u ZCRYPTO_PKCS11_SLOT \
    ZCRYPTO_PKCS11_MODULE="$module" \
    "$zig_bin" build pkcs11-integration -Dpkcs11=true --summary all
