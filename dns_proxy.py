# --- dns_proxy.py (session-aware stats, reset on app launch) ---
from dnslib import DNSRecord, RR, A, QTYPE
import socketserver, json, time, requests, os, threading, itertools, random, requests

BLOCKLIST = set()
WHITELIST = set()
STATS_FILE = "stats.json"
_STATS_LOCK = threading.Lock()

# --- DoH endpoints (host-based and IP-based mixed) ---
DOH_ENDPOINTS = [
    ("1.1.1.1", "cloudflare-dns.com"), 
    ("1.0.0.1", "cloudflare-dns.com"),
    ("8.8.8.8", "dns.google"),
    ("8.8.4.4", "dns.google"),
    ("9.9.9.9", "dns.quad9.net"),
    ("149.112.112.112", "dns.quad9.net"),
    ("94.140.14.14", "dns.adguard.com"),
    ("94.140.15.15", "dns.adguard.com"),
]

# Create a cycle iterator for round robin
_doh_cycle = itertools.cycle(DOH_ENDPOINTS)

def load_blocklist(path="blocklists/moderate.txt"):
    domains = set()
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "#" in line:
                line = line.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 2:
                for token in parts[1:]:
                    domains.add(token.lower())
            else:
                domains.add(parts[0].lower())
    return domains

def load_whitelist(path="whitelist.txt"):
    domains = set()
    if not os.path.exists(path):
        return domains
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            domains.add(line.lower())
    return domains

# ----- robust stats helpers (atomic writes, tolerant reads) -----
def _read_stats():
    try:
        with open(STATS_FILE, "r") as f:
            raw = f.read()
            if not raw.strip():
                raise ValueError("empty stats file")
            data = json.loads(raw)
    except (FileNotFoundError, json.JSONDecodeError, ValueError):
        data = {}

    # Ensure keys exist and are sane
    def _as_int(v, default=0):
        try:
            return int(v)
        except Exception:
            return default

    now = time.time()
    data.setdefault("blocked", 0)
    data.setdefault("allowed", 0)
    data.setdefault("last_reset", now)
    data.setdefault("session_blocked", 0)
    data.setdefault("session_allowed", 0)
    data.setdefault("session_started", now)

    data["blocked"] = _as_int(data.get("blocked", 0))
    data["allowed"] = _as_int(data.get("allowed", 0))
    data["session_blocked"] = _as_int(data.get("session_blocked", 0))
    data["session_allowed"] = _as_int(data.get("session_allowed", 0))
    if not isinstance(data.get("last_reset"), (int, float)):
        data["last_reset"] = now
    if not isinstance(data.get("session_started"), (int, float)):
        data["session_started"] = now

    return data

def _write_stats(stats: dict):
    tmp = STATS_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(stats, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, STATS_FILE)  # atomic on macOS

def start_new_session():
    """Reset only session counters; keep cumulative totals."""
    with _STATS_LOCK:
        stats = _read_stats()
        now = time.time()
        stats["blocked"] = int(stats.get("blocked", 0))
        stats["allowed"] = int(stats.get("allowed", 0))
        stats["session_blocked"] = 0
        stats["session_allowed"] = 0
        stats["session_started"] = now
        _write_stats(stats)

def update_stats(blocked: bool = False):
    with _STATS_LOCK:
        stats = _read_stats()
        key_cum = "blocked" if blocked else "allowed"
        key_ses = "session_blocked" if blocked else "session_allowed"
        stats[key_cum] = int(stats.get(key_cum, 0)) + 1
        stats[key_ses] = int(stats.get(key_ses, 0)) + 1
        _write_stats(stats)
# ----------------------------------------------------------------

# --- Round-robin index ---
_doh_index = 0

def doh_query(data: bytes):
    global _doh_index
    headers = {
        "Content-Type": "application/dns-message",
        "Accept": "application/dns-message"
    }

    # Try endpoints in round-robin
    for _ in range(len(DOH_ENDPOINTS)):
        ip, host = DOH_ENDPOINTS[_doh_index]
        _doh_index = (_doh_index + 1) % len(DOH_ENDPOINTS)

        try:
            # Always connect to IP, but optionally override Host/SNI
            url = f"https://{ip}/dns-query"
            req_headers = dict(headers)
            if host:
                req_headers["Host"] = host

            resp = requests.post(
                url,
                headers=req_headers,
                data=data,
                timeout=5,
                verify=True,
            )

            if resp.status_code == 200 and resp.content:
                return resp.content
            else:
                print(f"[!] DoH upstream {ip} (host={host}) returned {resp.status_code}")

        except Exception as e:
            print(f"[!] DoH lookup failed via {ip} (host={host}): {e}")

    return None



class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        request = DNSRecord.parse(data)
        qname = str(request.q.qname).rstrip(".").lower()

        IGNORE_PATTERNS = (".local", ".in-addr.arpa", "._dns-sd._udp")
        if any(qname.endswith(p) for p in IGNORE_PATTERNS):
            reply = request.reply()
            reply.header.rcode = 3  # NXDOMAIN
            sock.sendto(reply.pack(), self.client_address)
            update_stats(blocked=False)
            return

        if any(qname.endswith(domain) for domain in WHITELIST):
            resp = doh_query(data)
            if resp:
                sock.sendto(resp, self.client_address)
                update_stats(blocked=False)
            return

        if any(qname.endswith(domain) for domain in BLOCKLIST):
            reply = request.reply()
            reply.add_answer(RR(qname, QTYPE.A, rdata=A("0.0.0.0"), ttl=60))
            sock.sendto(reply.pack(), self.client_address)
            update_stats(blocked=True)
            return

        resp = doh_query(data)
        if resp:
            sock.sendto(resp, self.client_address)
            update_stats(blocked=False)
        else:
            print(f"[!] Upstream DoH query failed for {qname}")
            reply = request.reply()
            reply.header.rcode = 2
            sock.sendto(reply.pack(), self.client_address)

def run_dns(blocklists, stop_event=None, port=5300):
    global BLOCKLIST, WHITELIST
    BLOCKLIST = set()
    WHITELIST = load_whitelist()

    for path in blocklists:
        BLOCKLIST |= load_blocklist(path)

    BLOCKLIST -= WHITELIST

    print(f"[+] Loaded {len(BLOCKLIST)} domains into blocklist")
    print(f"[+] Loaded {len(WHITELIST)} domains into whitelist")

    with socketserver.UDPServer(("127.0.0.1", port), DNSHandler) as server:
        print(f"[+] DNS Proxy running on 127.0.0.1:{port} (DoH → multiple endpoints)")
        if stop_event is None:
            server.serve_forever()
        else:
            while not stop_event.is_set():
                server.handle_request()
            server.server_close()

if __name__ == "__main__":
    run_dns(["blocklists/moderate.txt"])
