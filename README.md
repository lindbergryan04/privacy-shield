# Privacy Shield v0.1.0

Looking to retain your humanity under the tin fist of Big Tech?  
**Privacy Shield** is a lightweight desktop app that blocks trackers at the DNS level and gives you real-time visibility into what’s being blocked.

It runs a local DNS-over-HTTPS (DoH) proxy with curated blocklists, a whitelist for safe domains, and a simple PyQt5 desktop UI.

---

## ✨ Features

- 🚫 **Block trackers & ads** at the DNS level  
- ✅ **Whitelist domains** you trust (e.g. Discord, Zoom)  
- 📊 **Live session stats**: trackers blocked in real time  
- 🔒 **DNS-over-HTTPS** using Cloudflare (with optional fallbacks)  
- 🖥️ **Cross-platform PyQt5 GUI**  
- ⚡ **No browser extensions required**

---

## 🔧 Setup

Clone and set up a virtual environment:

```bash
git clone https://github.com/you/privacy-shield
cd privacy-shield
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

---

## 🚀 Usage

Start the app:

```bash
python app.py
```

- Select one or more blocklists (Strict, Moderate, etc.)  
- Click **Start DNS Proxy**  
- All system DNS queries will be routed through Privacy Shield  
- Click **Stop DNS Proxy** to restore your system’s DNS configuration  

---

## 📂 File Structure

```
privacy-shield/
├── app.py           # PyQt5 GUI
├── dns_proxy.py     # DNS-over-HTTPS proxy
├── blocklists/      # Curated tracker/ad blocklists
├── whitelist.txt    # User whitelist (optional)
├── stats.json       # Session & cumulative stats
├── requirements.txt
└── README.md
```

---

## 📝 Notes

- On macOS, `pfctl` is used to transparently redirect DNS traffic.  
- Some local `.local`, `.arpa`, and `_dns-sd._udp` queries are ignored by design.  
- You may need `sudo` for DNS and packet filter configuration.  
- Whitelisted domains are always resolved upstream, even if they appear in blocklists.  
- Blocked domains are answered locally with `0.0.0.0`.  
- MacOS support only.

---

## 📜 License

This project is licensed under the **MIT License** — you are free to use, modify, and share it.
