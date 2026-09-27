#!/bin/bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
GO=${GO:-go}
if [[ ${1:-} == --help || $# -eq 0 ]]; then
    echo "usage: run.sh --run|--refusal"
    exit 0
fi
[[ $# -eq 1 && ( $1 == --run || $1 == --refusal ) ]] || exit 2
if [[ $1 == --refusal && ( -n ${OA_XPC_EXEC_WORK:-} || -n ${OA_XPC_EXEC_SERVICE:-} ) ]]; then
    echo "--refusal uses an owned temporary directory and service name" >&2
    exit 2
fi

WORK=${OA_XPC_EXEC_WORK:-$(mktemp -d /tmp/oa-xpc-exec.XXXXXX)}
mkdir -p "$WORK"
UID_VALUE=$(id -u)
SERVICE=${OA_XPC_EXEC_SERVICE:-com.openabstractions.test.exec.$UID_VALUE.$$}
BROKER_SERVICE="$SERVICE.broker"
DOMAIN="gui/$UID_VALUE"
SERVER="$WORK/server"
BROKER="$WORK/broker"
BEFORE="$WORK/before"
AFTER="$WORK/after"
OBSERVED="$WORK/observed.txt"
EFFECT="$WORK/effect.txt"
SERVER_PLIST="$WORK/server.plist"
BROKER_PLIST="$WORK/broker.plist"
SERVER_UP=0
BROKER_UP=0
CAFFEINATE_PID=""

cleanup() {
    [[ $SERVER_UP -eq 0 ]] || launchctl bootout "$DOMAIN/$SERVICE" >/dev/null 2>&1 || true
    [[ $BROKER_UP -eq 0 ]] || launchctl bootout "$DOMAIN/$BROKER_SERVICE" >/dev/null 2>&1 || true
    if [[ -n $CAFFEINATE_PID ]]; then
        kill "$CAFFEINATE_PID" >/dev/null 2>&1 || true
        wait "$CAFFEINATE_PID" >/dev/null 2>&1 || true
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM
caffeinate -dimsu -w $$ >/dev/null 2>&1 &
CAFFEINATE_PID=$!

if [[ $1 == --refusal ]]; then
    if ! launchctl print "$DOMAIN" >/dev/null 2>&1; then
        echo "$DOMAIN is unavailable; sign in to the Mac desktop before this XPC test" >&2
        exit 1
    fi
    (cd "$ROOT" && "$GO" build -o "$SERVER" ./listen/testdata/xpcrefusal)
    codesign --force --sign - --identifier org.openabstractions.xpcrefusal "$SERVER" >/dev/null
    cat >"$SERVER_PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>Label</key><string>$SERVICE</string>
<key>ProgramArguments</key><array><string>$SERVER</string><string>server</string><string>$SERVICE</string><string>$SERVER</string><string>$WORK/state</string></array>
<key>MachServices</key><dict><key>$SERVICE</key><true/></dict>
<key>RunAtLoad</key><true/>
<key>StandardErrorPath</key><string>$WORK/server.err</string></dict></plist>
EOF
    plutil -lint "$SERVER_PLIST" >/dev/null
    launchctl bootstrap "$DOMAIN" "$SERVER_PLIST"
    SERVER_UP=1
    for ((i = 0; i < 150; i++)); do
        [[ ! -f "$WORK/state.ready" ]] || break
        sleep 0.1
    done
    if [[ ! -f "$WORK/state.ready" ]]; then
        cat "$WORK/server.err" >&2
        echo "XPC refusal fixture did not become ready" >&2
        exit 1
    fi
    OA_TEST_UID="$UID_VALUE" "$SERVER" client "$SERVICE" "$SERVER" "$WORK/state"
    [[ ! -e "$WORK/state.dispatched" ]] || { echo "refused request reached application handler" >&2; exit 1; }
    echo "PASS exchange and one-way caller-proof refusal, zero application dispatches"
    exit 0
fi

(cd "$ROOT" && "$GO" build -o "$SERVER" ./listen/testdata/xpcexec)
clang -std=c17 -fblocks -Wall -Wextra -Werror -O2 \
    -DOA_VARIANT='"broker-build"' "$ROOT/listen/testdata/xpcexec/_exec_client.c" -o "$BROKER"
clang -std=c17 -fblocks -Wall -Wextra -Werror -O2 \
    -DOA_VARIANT='"before-exec-build"' "$ROOT/listen/testdata/xpcexec/_exec_client.c" -o "$BEFORE"
clang -std=c17 -fblocks -Wall -Wextra -Werror -O2 \
    -DOA_VARIANT='"after-exec-build"' "$ROOT/listen/testdata/xpcexec/_exec_client.c" -o "$AFTER"
codesign --force --sign - --identifier org.openabstractions.xpcexec.server "$SERVER" >/dev/null
codesign --force --sign - --identifier org.openabstractions.xpcexec.broker "$BROKER" >/dev/null
codesign --force --sign - --identifier org.openabstractions.xpcexec.before "$BEFORE" >/dev/null
codesign --force --sign - --identifier org.openabstractions.xpcexec.after "$AFTER" >/dev/null

cdhash() { codesign -dvvv "$1" 2>&1 | sed -n 's/^CDHash=//p'; }
SERVER_HASH=$(cdhash "$SERVER")
BROKER_HASH=$(cdhash "$BROKER")
BEFORE_HASH=$(cdhash "$BEFORE")
AFTER_HASH=$(cdhash "$AFTER")
[[ -n $SERVER_HASH && -n $BROKER_HASH && -n $BEFORE_HASH && -n $AFTER_HASH ]]
[[ $BEFORE_HASH != "$AFTER_HASH" ]]
SERVER_REQ="cdhash H\"$SERVER_HASH\""
BROKER_REQ="cdhash H\"$BROKER_HASH\""

cat >"$SERVER_PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>Label</key><string>$SERVICE</string>
<key>ProgramArguments</key><array><string>$SERVER</string><string>xpc:$SERVICE</string><string>$BEFORE</string><string>$OBSERVED</string><string>$EFFECT</string></array>
<key>MachServices</key><dict><key>$SERVICE</key><true/></dict>
<key>StandardErrorPath</key><string>$WORK/server.err</string></dict></plist>
EOF
cat >"$BROKER_PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>Label</key><string>$BROKER_SERVICE</string>
<key>ProgramArguments</key><array><string>$BROKER</string><string>--broker</string><string>$BROKER_SERVICE</string></array>
<key>MachServices</key><dict><key>$BROKER_SERVICE</key><true/></dict>
<key>StandardErrorPath</key><string>$WORK/broker.err</string></dict></plist>
EOF
plutil -lint "$SERVER_PLIST" "$BROKER_PLIST" >/dev/null
launchctl bootstrap "$DOMAIN" "$SERVER_PLIST"; SERVER_UP=1
launchctl bootstrap "$DOMAIN" "$BROKER_PLIST"; BROKER_UP=1

OUTPUT=$("$BEFORE" "$SERVICE" "$SERVER_REQ" "$BROKER_SERVICE" "$BROKER_REQ" "$AFTER")
echo "$OUTPUT"
grep -q 'result=refused same_pid=1' <<<"$OUTPUT"
grep -q 'error=Connection invalid' <<<"$OUTPUT"
[[ ! -e $OBSERVED && ! -e $EFFECT ]]
echo "before_cdhash=$BEFORE_HASH after_cdhash=$AFTER_HASH"
echo "PASS same-PID exec invalidated the retained production session before handler or effect"
