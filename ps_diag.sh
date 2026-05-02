#!/usr/bin/env bash
# Privacy Shield quick diagnostics (macOS)
set -u
sep(){ printf "\n----- %s -----\n" "$1"; }

sep "Detect service for en0"
SERVICE="$(networksetup -listallhardwareports | awk 'BEGIN{RS=""; FS="\n"} /Device: en0/{for(i=1;i<=NF;i++) if ($i ~ /^Hardware Port:/){sub(/Hardware Port: /,"",$i); print $i; exit}}')"
: "${SERVICE:=Wi-Fi}"
echo "Service: $SERVICE"

sep "Current DNS servers for service"
networksetup -getdnsservers "$SERVICE" || true

sep "Primary resolver from scutil --dns"
scutil --dns | sed -n '/Resolver #1/,/Resolver #/p' | sed '$d' || true

sep "PF status and PrivacyShield anchor rules"
sudo pfctl -s info | cat
sudo pfctl -s Anchors | grep -i PrivacyShield || true
sudo pfctl -a com.apple/PrivacyShield -sr | cat || true

sep "Is the UDP server listening on 127.0.0.1:5300?"
lsof -nP -iUDP:5300 || true

sep "Direct query to local proxy (bypasses PF by targeting 5300)"
dig @127.0.0.1 -p 5300 cloudflare.com +time=2 +tries=1 || true

sep "System default dig (should work if PF + DNS pointing to 127.0.0.1 are correct)"
dig cloudflare.com +time=2 +tries=1 || true

sep "Outbound connectivity check to DoH endpoint (TLS only, not a real DNS query)"
curl -s -o /dev/null -w "HTTPS to 1.1.1.1/dns-query -> HTTP %{http_code}\n" \
  -H 'accept: application/dns-message' -H 'content-type: application/dns-message' \
  --data-binary $'\x00' https://1.1.1.1/dns-query || true

sep "Recent stats.json (if present)"
[ -f stats.json ] && tail -n +1 stats.json || echo "stats.json not found"

sep "Optional fixes (uncomment to run)"
cat <<'FIXES'
# 1) Re-enable pf if disabled
# sudo pfctl -e

# 2) Flush only PrivacyShield anchor rules
# sudo pfctl -a com.apple/PrivacyShield -F all

# 3) Restore service DNS back to DHCP/default (then re-run app)
# networksetup -setdnsservers "$SERVICE" Empty

# 4) Point DNS to local again (what the app does)
# networksetup -setdnsservers "$SERVICE" 127.0.0.1
FIXES
