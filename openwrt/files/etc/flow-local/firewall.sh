#!/bin/sh
# flow-local transparent interception rules for OpenWrt fw4 (nftables).
#
# Intercepts traffic ONLY from the devices listed in /etc/flow-local/clients
# (one IP per line). Every other device on the LAN is left completely untouched,
# so the CA certificate only needs to be installed on the listed devices.
#
# Executed by fw4 on every firewall (re)build via /etc/config/firewall:
#   config include 'flow_local'
#       option path '/etc/flow-local/firewall.sh'

RIP="${RIP:-192.168.0.2}"        # router LAN IP (its own 80/443 stays untouched)
CLIENTS_FILE=/etc/flow-local/clients
HTTP_PORT=3128
HTTPS_PORT=8443

[ -s "$CLIENTS_FILE" ] || exit 0

# Build a comma-separated list for the nft anonymous set.
set=$(tr '\n ' ',' < "$CLIENTS_FILE" | tr -s ',' | sed 's/^,//; s/,$//')
[ -n "$set" ] || exit 0

# Redirect only the listed devices' HTTP/HTTPS to the transparent listeners.
nft add rule inet fw4 dstnat_lan ip saddr { $set } ip daddr != "$RIP" tcp dport 80 redirect to :$HTTP_PORT 2>/dev/null || true
nft add rule inet fw4 dstnat_lan ip saddr { $set } ip daddr != "$RIP" tcp dport 443 redirect to :$HTTPS_PORT 2>/dev/null || true

# Disable QUIC/HTTP3 (UDP 443) only for the listed devices, so their browsers
# fall back to TCP and the transparent HTTPS MITM can intercept.
nft insert rule inet fw4 forward_lan ip saddr { $set } udp dport 443 reject 2>/dev/null || true

exit 0
