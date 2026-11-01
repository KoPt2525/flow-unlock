#!/bin/sh
# Install flow-local on an OpenWrt router.
#
# Usage (run ON the router, after copying the repo + a compiled binary over):
#   sh install.sh <path-to-flow-local-binary> [--transparent]
#
# Examples:
#   # explicit proxy only (client sets proxy + trusts CA)
#   sh install.sh /tmp/flow-local-linux-arm64
#
#   # transparent interception (iptables REDIRECT of LAN 80/443)
#   sh install.sh /tmp/flow-local-linux-arm64 --transparent
#
# Uses only cp/chmod (busybox), no coreutils `install` dependency.
set -e

BIN=""
TRANSPARENT=0
LAN_IF="${LAN_IF:-br-lan}"

for a in "$@"; do
    case "$a" in
        --transparent) TRANSPARENT=1 ;;
        -*) echo "unknown option: $a" >&2; exit 1 ;;
        *) BIN="$a" ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Auto-detect the binary from ./dist when not given.
if [ -z "$BIN" ]; then
    BIN=$(ls "$SCRIPT_DIR"/dist/flow-local-linux-* 2>/dev/null | head -n1 || true)
fi
if [ -z "$BIN" ] || [ ! -f "$BIN" ]; then
    echo "usage: $0 <path-to-flow-local-binary> [--transparent]" >&2
    exit 1
fi

echo "installing binary: $BIN"
cp "$BIN" /usr/bin/flow-local
chmod 0755 /usr/bin/flow-local

cp "$SCRIPT_DIR/openwrt/files/etc/init.d/flow-local" /etc/init.d/flow-local
chmod 0755 /etc/init.d/flow-local
if [ ! -f /etc/config/flow-local ]; then
    cp "$SCRIPT_DIR/openwrt/files/etc/config/flow-local" /etc/config/flow-local
    chmod 0644 /etc/config/flow-local
fi

echo "generating CA (if missing)..."
/usr/bin/flow-local -gen-ca /etc/flow-local || true

if [ "$TRANSPARENT" = "1" ]; then
    echo "enabling transparent mode (nftables/fw4)..."
    uci set flow-local.flow.transparent=1
    uci commit flow-local

    mkdir -p /etc/flow-local
    cp "$SCRIPT_DIR/openwrt/files/etc/flow-local/firewall.sh" /etc/flow-local/firewall.sh
    chmod 0755 /etc/flow-local/firewall.sh
    [ -s /etc/flow-local/clients ] || touch /etc/flow-local/clients

    # Register the fw4 include (idempotent via section name).
    if ! grep -q "flow_local" /etc/config/firewall 2>/dev/null; then
        uci set firewall.flow_local=include
        uci set firewall.flow_local.path="/etc/flow-local/firewall.sh"
        uci set firewall.flow_local.enabled=1
        uci commit firewall
    fi

    /etc/init.d/firewall reload 2>/dev/null || true
    echo "transparent mode enabled. Add device IPs to /etc/flow-local/clients."
fi

/etc/init.d/flow-local enable
/etc/init.d/flow-local restart 2>/dev/null || /etc/init.d/flow-local start

echo ""
echo "Done."
echo "  CA certificate : /etc/flow-local/ca.crt"
echo "  Status         : flow-local -status   (or /tmp/flow-local/status.json)"
echo "  Toggle         : uci set flow-local.flow.enabled=0; uci commit flow-local; /etc/init.d/flow-local reload"
echo ""
if [ "$TRANSPARENT" = "1" ]; then
    echo "Install /etc/flow-local/ca.crt on the client. No proxy settings needed."
else
    echo "Install /etc/flow-local/ca.crt on the client and set the client proxy to this router :8080."
fi
