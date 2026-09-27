#!/bin/bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
IDENTITY_DIR=$(cd "$SCRIPT_DIR/../.." && pwd)
NODE=${NODE:-node}
GO=${GO:-go}
CMAKE=${CMAKE:-cmake}

if [[ ${1:-} == "--help" || $# -eq 0 ]]; then
    cat <<'EOF'
Usage: run-macos-xpc.sh --node | --rust | --all

Build the existing shared C transport and disposable Go XPC listener, register
one unique launchd service, run the selected language fixture, and remove the
service and temporary build tree. Rust requires an existing cargo executable;
this script never installs a toolchain.
EOF
    exit 0
fi
if [[ $# -ne 1 || ! $1 =~ ^--(node|rust|all)$ ]]; then
    echo "usage: run-macos-xpc.sh --node | --rust | --all" >&2
    exit 2
fi
MODE=${1#--}
WORK=${OA_XPC_WORK:-$(mktemp -d /tmp/oa-xpc-language-proof.XXXXXX)}
mkdir -p "$WORK"
UID_VALUE=$(id -u)
SERVICE=${OA_XPC_TEST_SERVICE:-com.openabstractions.test.language.$UID_VALUE.$$}
DOMAIN="gui/$UID_VALUE"
PLIST="$WORK/$SERVICE.plist"
SERVER="$WORK/xpcserver"
PREFIX="$WORK/prefix"
CAFFEINATE_PID=""
BOOTSTRAPPED=0

cleanup() {
    if [[ $BOOTSTRAPPED -eq 1 ]]; then
        launchctl bootout "$DOMAIN/$SERVICE" >/dev/null 2>&1 || true
    fi
    if [[ -n $CAFFEINATE_PID ]]; then
        kill "$CAFFEINATE_PID" >/dev/null 2>&1 || true
        wait "$CAFFEINATE_PID" >/dev/null 2>&1 || true
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

caffeinate -dimsu -w $$ >/dev/null 2>&1 &
CAFFEINATE_PID=$!

"$CMAKE" -S "$IDENTITY_DIR/cpp" -B "$WORK/cpp" \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$PREFIX" \
    -DABSTRACTION_IPC_BUILD_TESTS=OFF
"$CMAKE" --build "$WORK/cpp" --config Release --parallel
"$CMAKE" --install "$WORK/cpp" --config Release

(cd "$IDENTITY_DIR" && "$GO" build -o "$SERVER" ./listen/testdata/xpcserver)
codesign --force --sign - "$SERVER" >/dev/null

cat >"$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>$SERVICE</string>
<key>ProgramArguments</key><array><string>$SERVER</string><string>xpc:$SERVICE</string></array>
<key>MachServices</key><dict><key>$SERVICE</key><true/></dict>
<key>StandardOutPath</key><string>$WORK/server.out</string>
<key>StandardErrorPath</key><string>$WORK/server.err</string>
</dict></plist>
EOF
plutil -lint "$PLIST" >/dev/null
launchctl bootstrap "$DOMAIN" "$PLIST"
BOOTSTRAPPED=1

export OA_XPC_TEST_SERVICE="$SERVICE"
export OA_XPC_TEST_PROGRAM="$SERVER"
export OA_XPC_TEST_UID="$UID_VALUE"

if [[ $MODE == node || $MODE == all ]]; then
    test -x "$NODE"
    NODE_INCLUDE_DIR=$(cd "$(dirname "$NODE")/../include/node" && pwd)
    "$CMAKE" -S "$IDENTITY_DIR/javascript" -B "$WORK/node" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_PREFIX_PATH="$PREFIX" \
        -DNODE_INCLUDE_DIR="$NODE_INCLUDE_DIR"
    "$CMAKE" --build "$WORK/node" --config Release --parallel
    codesign --force --sign - "$WORK/node/oa_ipc_node.node" >/dev/null
    ABSTRACTION_IPC_NODE="$WORK/node/oa_ipc_node.node" \
        "$NODE" --test "$SCRIPT_DIR/xpc.test.mjs"
fi

if [[ $MODE == rust || $MODE == all ]]; then
    if ! command -v cargo >/dev/null 2>&1; then
        echo "existing cargo executable required for Rust runtime proof" >&2
        exit 3
    fi
    CARGO_HOME="$WORK/cargo-home" CARGO_TARGET_DIR="$WORK/cargo-target" \
        OA_IPC_PREFIX="$PREFIX" cargo test --offline \
        --manifest-path "$IDENTITY_DIR/rust/Cargo.toml" --test xpc
fi
