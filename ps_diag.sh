#!/usr/bin/env bash
# Privacy Shield quick diagnostics (macOS). Read-only; run with sudo to also check old pf rules.
set -u
sep(){ printf "\n----- %s -----\n" "$1"; }
SUPPORT="$HOME/Library/Application Support/PrivacyShield"
[ -n "${SUDO_USER:-}" ] && SUPPORT="$(eval echo "~$SUDO_USER")/Library/Application Support/PrivacyShield"
LOGS="$(dirname "$(dirname "$SUPPORT")")/Logs/PrivacyShield"
MULLVAD="$(command -v mullvad || echo "/Applications/Mullvad VPN.app/Contents/Resources/mullvad")"

sep "DNS servers set on each network service (none = automatic from DHCP)"
networksetup -listallnetworkservices | tail -n +2 | while IFS= read -r svc; do
  printf '%-28s %s\n' "${svc#\*}:" "$(networksetup -getdnsservers "${svc#\*}" | tr '\n' ' ')"
done

sep "Resolver macOS is actually using"
scutil --dns | awk '/^resolver #1/ && !done { on = 1 } on { print } on && /^$/ { on = 0; done = 1 }'

sep "Mullvad"
if [ -x "$MULLVAD" ]; then
  "$MULLVAD" status | head -1
  "$MULLVAD" dns get
else
  echo "not installed"
fi

sep "Who is listening on port 53"
netstat -anv -p udp | awk '$4 ~ /\.53$/ { p = "?"; for (i = 5; i <= NF; i++) if ($i ~ /^[^:]+:[0-9]+$/) p = $i; print $1, $4, p }'
echo "(127.0.0.1.53 should be python while the shield is on; Mullvad's own resolver uses another 127.x address)"

sep "Ask the shield directly (127.0.0.1:53; times out while the shield is off)"
dig @127.0.0.1 example.com +time=2 +tries=1 +short || true

sep "Ask the way apps do (system resolver)"
dscacheutil -q host -a name example.com | head -4

sep "Can we reach DNS-over-HTTPS? (Cloudflare, JSON API)"
curl -s -m 5 -o /dev/null -w "https://1.1.1.1/dns-query -> HTTP %{http_code}\n" \
  -H 'accept: application/dns-json' 'https://1.1.1.1/dns-query?name=example.com&type=A' || echo "unreachable"

sep "Saved settings from a session that hasn't been restored"
if [ -f "$SUPPORT/state.json" ]; then
  cat "$SUPPORT/state.json"
  echo; echo "Put them back with the command at the bottom."
else
  echo "none (good)"
fi

sep "Helper log (last 15 lines)"
[ -f "$LOGS/helper.log" ] && tail -n 15 "$LOGS/helper.log" || echo "no log at $LOGS/helper.log"

sep "App log, built app only (last 15 lines)"
[ -f "$LOGS/app.log" ] && tail -n 15 "$LOGS/app.log" || echo "no log at $LOGS/app.log"

sep "Leftover pf rules from v0.1 (needs sudo)"
if [ "$(id -u)" -eq 0 ]; then
  pfctl -a com.apple/PrivacyShield -sn 2>/dev/null | grep . || echo "none"
else
  echo "skipped; run: sudo ./ps_diag.sh"
fi

sep "If websites won't load"
cat <<'FIXES'
# Put back everything Privacy Shield changed (uses the saved settings above; without them it
# resets anything still pointing at 127.0.0.1 to automatic). From the project folder:
sudo python3 shield_helper.py --restore

# Or with the built app:
sudo ~/Applications/"Privacy Shield.app"/Contents/MacOS/"Privacy Shield" --helper --restore

# Check the built app end to end without changing any settings:
~/Applications/"Privacy Shield.app"/Contents/MacOS/"Privacy Shield" --selftest

# Manual version of the same thing:
# sudo networksetup -setdnsservers Wi-Fi Empty
# mullvad dns set default
FIXES
