# Privacy Shield v0.2.0

Looking to retain your humanity under the tin fist of Big Tech?  
**Privacy Shield** is a lightweight desktop app that blocks trackers at the DNS level and gives you real-time visibility into what’s being blocked.

It runs a local DNS server that answers blocklisted domains itself and sends everything else over DNS-over-HTTPS, with a whitelist for safe domains and a simple PyQt5 desktop UI. It works with or without Mullvad VPN.

---

## ✨ Features

- 🚫 **Block trackers & ads** at the DNS level (a listed domain blocks its subdomains too)
- ➕ **Add your own blocklists** from a URL or a file (hosts, plain domains, or `||domain^` format)
- ⛔ **Blacklist / whitelist**: always block or always allow any domain, right from the app
- 📊 **Live session stats** and a list of what was just blocked
- ⚡ **Fast**: answers are cached, so repeat lookups take about a millisecond instead of a round trip
- 🔒 **DNS-over-HTTPS** via Cloudflare, failing over to Google
- 🛡️ **Works with Mullvad VPN**, connected or not
- 🧯 **Can't strand you offline**: DNS is put back when you stop, quit, or crash
- 🖥️ **PyQt5 GUI**, no browser extensions required

---

## 🔧 Setup

Clone and set up a virtual environment:

```bash
git clone https://github.com/you/privacy-shield
cd privacy-shield
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## 🖥️ Build the Mac app

```bash
./build_app.sh
```

This builds **Privacy Shield.app** with PyInstaller and puts it in `~/Applications`, so you can open it from Spotlight, Launchpad, or the Dock like any other app. It bundles its own Python, so it doesn't need the terminal or the venv. Run the script again after changing the code.

## 🚀 Usage

Open **Privacy Shield** (or run `python app.py` from the project folder).

- Tick one or more blocklists (Strict, Moderate, etc.); the menu stays open until you click away. Your choice is remembered.
- **Custom lists…** adds your own lists from a URL or a file. Lists from a URL are re-downloaded weekly.
- Click **Start DNS Proxy**. macOS asks for your password once per app session.
- The status turns **Protected**. Blocked domains show up in the list as they happen. If a site breaks, double-click the domain to allow it.
- Type a domain (or paste a URL) and click **Block** or **Allow** to always block or always allow it. This takes effect within a second or two, even while protection is on.
- Click **Stop DNS Proxy**, or just quit, to put your DNS settings back.

To try the app without the password prompt or changing any settings:

```bash
PRIVACY_SHIELD_DRY_RUN=1 python app.py
```

It serves on port 5300 instead of 53 and writes what it *would* change to the helper log.

---

## ⚙️ How it works

Two processes:

- **`app.py`** (runs as you) does all the DNS work: it answers blocked names with `0.0.0.0` / `::`, and forwards everything else over DNS-over-HTTPS with kept-alive connections. Lookups run in parallel. Answers are cached for as long as their TTL allows, and an answer that expired less than an hour ago is served right away while a fresh one is fetched. If an upstream is slow to answer, the next one is asked too and the first answer wins. When the route to the internet changes (VPN on or off, new Wi-Fi), old connections are dropped immediately instead of being waited out.
- **`shield_helper.py`** (runs as root, started through the password prompt) does only what needs root. It opens port 53 on `127.0.0.1` and hands the socket to the app. It points DNS at `127.0.0.1` for every network service and, if Mullvad is installed, sets Mullvad's custom DNS to `127.0.0.1`. When the shield stops, it puts both back.

Before touching any settings, the app checks that it can actually resolve a name through the shield. If that fails, your settings are left alone.

The helper puts your DNS back when you click Stop or quit. It also does this if the app crashes or is force-quit, or if the shield stops answering for about 30 seconds.

If no DNS-over-HTTPS server is reachable (captive-portal Wi-Fi at a hotel or airport, a network that blocks DoH), queries fall back to the network's own DNS server so you can still log in. Blocking still applies. The app shows which upstream is in use. Set `FALLBACK_TO_NETWORK_DNS = False` in `dns_proxy.py` to fail closed instead.

## 🛡️ Mullvad VPN

While Mullvad is connected it takes over system DNS. It sends queries to its own local resolver, which forwards them to Mullvad's DNS server, or to your **custom DNS server** if you set one. So while the shield is on, Mullvad's custom DNS is set to `127.0.0.1` and Mullvad forwards everything through the shield. The shield's own lookups go out as DNS-over-HTTPS inside the tunnel, which Mullvad's firewall allows.

You don't need to change anything in Mullvad. When the shield stops, Mullvad's DNS setting (including any of its own content blockers) is restored exactly. Connecting or disconnecting the VPN while the shield is on is fine.

---

## 🧯 If websites won't load

Something went badly wrong (power loss, `kill -9`) and your DNS still points at the shield. Run this from the project folder:

```bash
sudo python3 shield_helper.py --restore
```

With the built app, the same thing is:

```bash
sudo ~/Applications/"Privacy Shield.app"/Contents/MacOS/"Privacy Shield" --helper --restore
```

It restores the settings saved in `~/Library/Application Support/PrivacyShield/state.json`. Without that file, it resets anything still pointing at `127.0.0.1` to automatic. The app also offers to do this the next time it starts.

To check the built app end to end without changing any settings, run it with `--selftest`.

`./ps_diag.sh` shows the current DNS settings, Mullvad's state, what's listening on port 53, and the logs in `~/Library/Logs/PrivacyShield/`.

To test the DNS filter by itself on an unprivileged port:

```bash
python dns_proxy.py --port 5300 --lists moderate social
dig @127.0.0.1 -p 5300 doubleclick.net
```

---

## 📂 File Structure

```
privacy-shield/
├── app.py              # PyQt5 GUI; runs the DNS filter
├── dns_proxy.py        # DNS filter + DNS-over-HTTPS upstreams
├── shield_helper.py    # the only part that runs as root: port 53 + DNS settings
├── launcher.py         # entry point of the built app
├── PrivacyShield.spec  # PyInstaller recipe
├── build_app.sh        # builds and installs Privacy Shield.app
├── assets/             # app icon (make_icon.py draws it)
├── ps_diag.sh          # diagnostics
├── blocklists/         # Curated tracker/ad blocklists
├── whitelist.txt       # Domains always allowed (optional, one per line)
├── blacklist.txt       # Domains always blocked (optional, one per line)
├── stats.json          # Session & cumulative stats
├── requirements.txt
└── README.md
```

---

## 📝 Notes

- A listed domain also blocks its subdomains (`doubleclick.net` blocks `ad.doubleclick.net`), matched on whole labels, so `x.com` doesn't block `netflix.com`.
- Your blacklist and whitelist beat the blocklists. Between the two, the more specific entry wins: whitelisting `example.com` and blacklisting `ads.example.com` blocks only `ads.example.com`. A tie goes to the whitelist. Edits take effect within a second or two, no restart needed.
- The built app keeps your whitelist, blacklist and stats in `~/Library/Application Support/PrivacyShield/` (the first build copies in `whitelist.txt` and `blacklist.txt`). Running from source uses the copies in the project folder. Lists you add under **Custom lists…** live in `~/Library/Application Support/PrivacyShield/blocklists/` either way.
- Answered locally and never forwarded: `.local` names, single-label names, reverse lookups for private IPs, and `use-application-dns.net` (which tells Firefox to use the system resolver instead of its own built-in DoH).
- DNS-over-HTTPS upstreams are listed at the top of `dns_proxy.py`. They're reached by IP (no DNS needed to find them) and certificates are checked against the real hostname.
- macOS only.

---

## 📜 License

This project is licensed under the **MIT License** — you are free to use, modify, and share it.
