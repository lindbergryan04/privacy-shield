# --- dns_proxy.py ---
"""Privacy Shield's DNS filter.

Answers queries for blocked domains locally and forwards everything else over DNS-over-HTTPS,
caching the answers. It serves on sockets it is handed (app.py gets them from shield_helper.py,
which binds 127.0.0.1:53 as root), so none of this code runs as root.

To try it by itself on an unprivileged port:
    python dns_proxy.py --port 5300 --lists moderate social
    dig @127.0.0.1 -p 5300 doubleclick.net
"""
import argparse, collections, datetime, ipaddress, itertools, json, os, re, socket, sqlite3, ssl, struct
import subprocess, sys, threading, time
from contextlib import closing
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait

import certifi, urllib3
from dnslib import AAAA, QTYPE, RCODE, RR, A, DNSRecord

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FROZEN = getattr(sys, "frozen", False)
SUPPORT_DIR = os.path.expanduser("~/Library/Application Support/PrivacyShield")
# From source, your whitelist, blacklist and stats live in the repo. In the built .app the bundle
# is read-only, so they live in Application Support instead.
DATA_DIR = SUPPORT_DIR if FROZEN else BASE_DIR
BUILTIN_LIST_DIR = os.path.join(BASE_DIR, "blocklists")
CUSTOM_LIST_DIR = os.path.join(SUPPORT_DIR, "blocklists")  # lists you add; shared by app and source
WHITELIST_FILE = os.path.join(DATA_DIR, "whitelist.txt")
BLACKLIST_FILE = os.path.join(DATA_DIR, "blacklist.txt")
STATS_DB = os.path.join(SUPPORT_DIR, "stats.db")  # all-time history; shared by app and source
# Where older versions kept their totals (the app's, and the repo's when running from source).
# Both are carried over into stats.db once.
LEGACY_STATS = sorted({os.path.join(SUPPORT_DIR, "stats.json"), os.path.join(DATA_DIR, "stats.json")})
if FROZEN:
    os.makedirs(DATA_DIR, exist_ok=True)

# DNS-over-HTTPS upstreams, tried in order. We connect by IP so finding the DNS server doesn't
# itself need DNS, but the TLS certificate is still checked against the hostname. (Quad9 and
# Mullvad's DoH servers only speak HTTP/2, which this client doesn't.)
DOH_UPSTREAMS = [
    ("Cloudflare", "1.1.1.1", "cloudflare-dns.com"),
    ("Cloudflare", "1.0.0.1", "cloudflare-dns.com"),
    ("Google", "8.8.8.8", "dns.google"),
    ("Google", "8.8.4.4", "dns.google"),
]
UPSTREAM_COOLDOWN = 30  # seconds to skip an upstream after it fails
HEDGE_MIN = 0.25        # ask the next upstream too once the first has taken max(this, 3x usual)

# If no DoH upstream answers (captive-portal Wi-Fi, a network that blocks DoH), ask the
# network's own DNS server so you can still get online. Blocking still applies. Set to False
# to fail closed instead.
FALLBACK_TO_NETWORK_DNS = True

CACHE_SIZE = 10000  # answers kept
MAX_TTL = 86400
STALE_FOR = 3600    # an expired answer is still served (then refreshed) for up to this long
STALE_TTL = 30      # the TTL such an answer goes out with
BLOCK_TTL = 10      # short, so whitelisting something takes effect almost right away
WORKERS = 32
LIST_REFRESH_AGE = 7 * 86400  # re-download lists added from a URL after this long
MAX_LIST_BYTES = 50 * 1024 * 1024

# Answered with NXDOMAIN here and never forwarded: mDNS names, reverse lookups for private
# addresses, the resolver-discovery zone, and Firefox's canary domain (NXDOMAIN tells Firefox
# to stop using its own built-in DoH and use the system resolver, i.e. us).
_LOCAL_ZONES = (
    ["local", "resolver.arpa", "use-application-dns.net"]
    + ["10.in-addr.arpa", "127.in-addr.arpa", "168.192.in-addr.arpa", "254.169.in-addr.arpa"]
    + [f"{i}.172.in-addr.arpa" for i in range(16, 32)]
    + ["d.f.ip6.arpa", "8.e.f.ip6.arpa", "9.e.f.ip6.arpa", "a.e.f.ip6.arpa", "b.e.f.ip6.arpa"]
)
_DOMAIN_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-_.")
_SSL_CONTEXT = ssl.create_default_context(cafile=certifi.where())


# ----- blocklists -----
def available_blocklists():
    """{name: path} for the bundled lists and the ones you added."""
    lists = {}
    for folder, custom in ((BUILTIN_LIST_DIR, False), (CUSTOM_LIST_DIR, True)):
        if os.path.isdir(folder):
            for f in sorted(os.listdir(folder)):
                if f.endswith(".txt"):
                    lists[f[:-4] if custom else f[:-4].capitalize()] = os.path.join(folder, f)
    return lists


def blocklist_path(name):
    return next((p for n, p in available_blocklists().items() if n.lower() == name.lower()), None)


def clean_domain(token):
    """Normalize one list entry. None for anything that isn't a multi-label hostname
    (hosts-file boilerplate like "localhost" or "0.0.0.0", junk like "!")."""
    name = token.lower().rstrip(".")
    if name.startswith("*."):
        name = name[2:]
    if "." not in name or name.startswith(".") or ".." in name or not set(name) <= _DOMAIN_CHARS:
        return None
    if name[-1].isdigit():
        try:
            ipaddress.ip_address(name)
            return None
        except ValueError:
            pass
    return name


_ZONE_WORDS = frozenset({"SOA", "NS", "IN", "CNAME", "A", "AAAA", "TXT"})


def parse_domains(lines):
    """Domains from hosts-file lines ("0.0.0.0 ads.example.com"), plain lists ("ads.example.com"
    or "*.ads.example.com"), adblock rules ("||ads.example.com^"), dnsmasq rules
    ("local=/ads.example.com/") and RPZ zones ("ads.example.com CNAME ."). Comments and other
    rule types are skipped."""
    domains = set()
    for line in lines:
        line = line.strip()
        if not line or line[0] in "#![;$@":  # comments, adblock headers, zone-file directives
            continue
        if line.startswith("||"):
            if line.endswith("^") and "$" not in line and "/" not in line:
                name = clean_domain(line[2:-1])
                if name:
                    domains.add(name)
            continue
        if line.startswith(("local=/", "address=/", "server=/")):
            name = clean_domain(line.split("/")[1])
            if name:
                domains.add(name)
            continue
        parts = line.split("#", 1)[0].split()
        if len(parts) > 1 and (parts[0] in _ZONE_WORDS or parts[1] in _ZONE_WORDS):
            if parts[1] == "CNAME" and parts[-1] == ".":  # RPZ: "ads.example.com CNAME ." blocks it
                name = clean_domain(parts[0])
                if name:
                    domains.add(name)
            continue  # other zone-file records (SOA, NS) aren't rules
        for token in parts[1:] if len(parts) > 1 else parts:
            name = clean_domain(token)
            if name:
                domains.add(name)
    return domains


def load_blocklist(path):
    with open(path, encoding="utf-8", errors="ignore") as f:
        return parse_domains(f)


def load_user_list(path):
    """Your whitelist or blacklist; a missing file is just empty."""
    return load_blocklist(path) if os.path.exists(path) else set()


def _match(name, domains):
    """The entry in domains covering name, most specific first: name itself or a parent domain
    (ads.example.com matches example.com, but dropbox.com does not match x.com)."""
    while name:
        if name in domains:
            return name
        name = name.partition(".")[2]
    return None


def _local_only(qname):
    if qname and "." not in qname:
        return True  # single-label names ("router", "wpad") don't exist on the internet
    return any(qname == z or qname.endswith("." + z) for z in _LOCAL_ZONES)


# ----- lists you add -----
_LIST_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._-]{0,39}")


def custom_lists():
    """Lists you added: [{"name", "path", "source", "domains", "updated"}], sorted by name."""
    lists = []
    if os.path.isdir(CUSTOM_LIST_DIR):
        for f in sorted(os.listdir(CUSTOM_LIST_DIR), key=str.lower):
            if not f.endswith(".txt"):
                continue
            path = os.path.join(CUSTOM_LIST_DIR, f)
            info = {"name": f[:-4], "path": path, "source": "", "domains": None,
                    "updated": os.path.getmtime(path)}
            with open(path, encoding="utf-8", errors="ignore") as fh:
                for line in itertools.islice(fh, 4):  # the header _save_list writes
                    if line.startswith("# Source: "):
                        info["source"] = line[10:].strip()
                    elif line.startswith("# Domains: "):
                        info["domains"] = int(line[11:].strip() or 0)
            lists.append(info)
    return lists


def add_custom_list(name, source):
    """Save the list at source (a URL or a file) as name. Returns how many domains it has."""
    name = name.strip()
    if not _LIST_NAME.fullmatch(name):
        raise ValueError("Use a short name made of letters, numbers, spaces, dots, dashes or underscores.")
    if blocklist_path(name):
        raise ValueError(f"There's already a list called {name}.")
    return _save_list(name, source)


def update_custom_list(name):
    """Fetch a list you added from its source again. Returns how many domains it has now."""
    info = next((i for i in custom_lists() if i["name"] == name), None)
    if not info or not info["source"]:
        raise ValueError(f"Don't know where {name} came from.")
    return _save_list(name, info["source"])


def refresh_custom_lists(max_age=LIST_REFRESH_AGE):
    """Re-download the URL lists older than max_age. Returns {name: domain count or error}."""
    results = {}
    for info in custom_lists():
        if info["source"].startswith(("http://", "https://")) and time.time() - info["updated"] > max_age:
            try:
                results[info["name"]] = _save_list(info["name"], info["source"])
            except Exception as e:
                results[info["name"]] = f"failed: {e}"
    return results


def remove_custom_list(name):
    os.remove(os.path.join(CUSTOM_LIST_DIR, f"{name}.txt"))


def _save_list(name, source):
    if source.startswith(("http://", "https://")):
        text = _download(source)
    else:
        with open(os.path.expanduser(source), encoding="utf-8", errors="ignore") as f:
            text = f.read(MAX_LIST_BYTES)
    domains = parse_domains(text.splitlines())
    if not domains:
        raise ValueError("That doesn't look like a blocklist: no domains in it.")
    os.makedirs(CUSTOM_LIST_DIR, exist_ok=True)
    path = os.path.join(CUSTOM_LIST_DIR, f"{name}.txt")
    with open(path + ".tmp", "w") as f:
        f.write(f"# Privacy Shield list\n# Source: {source}\n# Domains: {len(domains)}\n")
        f.write("\n".join(sorted(domains)) + "\n")
    os.replace(path + ".tmp", path)
    return len(domains)


def _download(url):
    """The text at url. Looked up through the system resolver, which is the shield while it's on."""
    http = urllib3.PoolManager(ssl_context=_SSL_CONTEXT, retries=urllib3.Retry(2, redirect=5),
                               timeout=urllib3.Timeout(connect=10, read=30))
    try:
        resp = http.request("GET", url, preload_content=False,
                            headers={"Accept-Encoding": "gzip", "User-Agent": "PrivacyShield"})
    except urllib3.exceptions.HTTPError as e:
        raise ValueError(f"Couldn't download it ({getattr(e, 'reason', None) or e})")
    try:
        if resp.status != 200:
            raise ValueError(f"The server said HTTP {resp.status}.")
        chunks, size = [], 0
        # decode_content must be explicit: without it, chunked gzip responses (jsDelivr sends
        # those) come through still compressed.
        for chunk in resp.stream(65536, decode_content=True):
            size += len(chunk)
            if size > MAX_LIST_BYTES:
                raise ValueError("That's over 50 MB. Is it the right URL?")
            chunks.append(chunk)
    finally:
        resp.release_conn()
    return b"".join(chunks).decode("utf-8", errors="ignore")


# ----- stats: live counters for the window, plus all-time history in SQLite -----
BLACKLIST_NAME = "Your blacklist"  # how blocks by your blacklist show up in the stats

_SCHEMA = """
CREATE TABLE IF NOT EXISTS hourly (hour INTEGER PRIMARY KEY, blocked INTEGER NOT NULL,
    allowed INTEGER NOT NULL, cached INTEGER NOT NULL, failed INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS domains (day TEXT NOT NULL, domain TEXT NOT NULL,
    blocked INTEGER NOT NULL, PRIMARY KEY (day, domain)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS lists (day TEXT NOT NULL, list TEXT NOT NULL,
    blocked INTEGER NOT NULL, PRIMARY KEY (day, list)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""
_BLOCKED, _ALLOWED, _CACHED, _FAILED = range(4)


def _add_months(dt, n):
    years, month = divmod(dt.month - 1 + n, 12)
    return dt.replace(year=dt.year + years, month=month + 1)


def _bucket_start(dt, unit):
    dt = dt.replace(minute=0, second=0, microsecond=0)
    if unit == "hour":
        return dt
    dt = dt.replace(hour=0)
    return dt if unit == "day" else dt.replace(day=1)


class Stats:
    """Counters for the window, and all-time history in a small SQLite database written about
    once a second. Blocked domains are recorded by name; allowed lookups are only counted, so
    the history never says which sites you visited."""

    def __init__(self, path=STATS_DB, legacy=LEGACY_STATS):
        self.path = path
        self.legacy = [legacy] if isinstance(legacy, str) else list(legacy)
        self.lock = threading.Lock()
        self.session_blocked = self.session_allowed = self.failed = self.cache_hits = 0
        self.recent = collections.deque(maxlen=200)  # (time, name) of recent blocks
        self._counts = collections.Counter()   # (hour, field) -> n, not written yet
        self._domains = collections.Counter()  # (day, domain) -> n
        self._lists = collections.Counter()    # (day, list) -> n
        self._opened = False  # the database is opened on first use, not at import

    @property
    def total_blocked(self):
        self._open()
        return self._baseline[0] + self._stored[0] + self._counted[0]

    @property
    def total_allowed(self):
        self._open()
        return self._baseline[1] + self._stored[1] + self._counted[1]

    @property
    def since(self):
        self._open()
        return self._since

    def _connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        db.execute("PRAGMA journal_mode=WAL")  # the analytics page can read while we write
        return db

    def _open(self):
        if self._opened:
            return
        with self.lock:
            if self._opened:
                return
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            with closing(self._connect()) as db, db:
                db.executescript(_SCHEMA)
                meta = dict(db.execute("SELECT key, value FROM meta"))
                if not meta:  # first run: carry over the totals older versions kept
                    meta = self._legacy_totals()
                    db.executemany("INSERT INTO meta VALUES (?, ?)", meta.items())
                blocked, allowed = db.execute("SELECT TOTAL(blocked), TOTAL(allowed) FROM hourly").fetchone()
            self._since = float(meta["since"])
            self._baseline = (int(meta["baseline_blocked"]), int(meta["baseline_allowed"]))
            self._stored = (int(blocked), int(allowed))  # already in the database at startup
            self._counted = [0, 0]                        # counted by this process since
            self._opened = True

    def _legacy_totals(self):
        since, blocked, allowed = time.time(), 0, 0
        for path in self.legacy:
            try:
                with open(path) as f:
                    old = json.load(f)
            except (OSError, ValueError):
                continue
            if not isinstance(old, dict):
                continue
            num = lambda key: old.get(key) if isinstance(old.get(key), (int, float)) else 0  # noqa: E731
            blocked, allowed = blocked + int(num("blocked")), allowed + int(num("allowed"))
            if num("last_reset"):
                since = min(since, num("last_reset"))
        return {"since": str(since), "baseline_blocked": str(blocked), "baseline_allowed": str(allowed)}

    def new_session(self):
        with self.lock:
            self.session_blocked = self.session_allowed = self.failed = self.cache_hits = 0
            self.recent.clear()

    def record(self, blocked, name=None, cached=False, source=None):
        self._open()
        now = time.time()
        hour = int(now // 3600)
        with self.lock:
            if blocked:
                self._counts[hour, _BLOCKED] += 1
                self.session_blocked += 1
                self._counted[0] += 1
                self.recent.append((now, name))
                day = time.strftime("%Y-%m-%d", time.localtime(now))
                self._domains[day, name] += 1
                if source:
                    self._lists[day, source] += 1
            else:
                self._counts[hour, _ALLOWED] += 1
                self.session_allowed += 1
                self._counted[1] += 1
                if cached:
                    self._counts[hour, _CACHED] += 1
                    self.cache_hits += 1

    def record_failure(self):
        self._open()
        with self.lock:
            self._counts[int(time.time() // 3600), _FAILED] += 1
            self.failed += 1

    def recent_blocked(self, limit=50):
        """Most recently blocked names, newest first, without repeats."""
        with self.lock:
            entries = list(self.recent)
        seen, names = set(), []
        for _, name in reversed(entries):
            if name not in seen:
                seen.add(name)
                names.append(name)
                if len(names) == limit:
                    break
        return names

    def flush(self):
        """Write what's been counted since the last flush."""
        if not self._opened:
            return  # nothing counted yet
        with self.lock:
            counts, domains, lists = self._counts, self._domains, self._lists
            if not (counts or domains or lists):
                return
            self._counts, self._domains, self._lists = (collections.Counter(), collections.Counter(),
                                                        collections.Counter())
        rows = collections.defaultdict(lambda: [0, 0, 0, 0])
        for (hour, field), n in counts.items():
            rows[hour][field] += n
        try:
            with closing(self._connect()) as db, db:
                db.executemany(
                    "INSERT INTO hourly VALUES (?, ?, ?, ?, ?) ON CONFLICT (hour) DO UPDATE SET "
                    "blocked = blocked + excluded.blocked, allowed = allowed + excluded.allowed, "
                    "cached = cached + excluded.cached, failed = failed + excluded.failed",
                    [(hour, *r) for hour, r in rows.items()])
                for table, column, counter in (("domains", "domain", domains), ("lists", "list", lists)):
                    db.executemany(
                        f"INSERT INTO {table} VALUES (?, ?, ?) ON CONFLICT (day, {column}) "
                        "DO UPDATE SET blocked = blocked + excluded.blocked",
                        [(*key, n) for key, n in counter.items()])
        except sqlite3.Error as e:
            print(f"[!] Couldn't save stats: {e}")
            with self.lock:  # keep them for the next try
                self._counts.update(counts)
                self._domains.update(domains)
                self._lists.update(lists)

    def report(self, period):
        """Numbers for the analytics page. period is "today", "30d", "12m" or "all"."""
        self._open()
        self.flush()
        now = datetime.datetime.now()
        today = _bucket_start(now, "day")
        with closing(self._connect()) as db:
            if period == "today":
                start, unit, count = today, "hour", 24
            elif period == "30d":
                start, unit, count = today - datetime.timedelta(days=29), "day", 30
            elif period == "12m":
                start, unit, count = _add_months(_bucket_start(now, "month"), -11), "month", 12
            else:
                first = db.execute("SELECT MIN(hour) FROM hourly").fetchone()[0]
                start = _bucket_start(datetime.datetime.fromtimestamp(first * 3600) if first else now, "month")
                unit = "month"
                count = (now.year - start.year) * 12 + now.month - start.month + 1
            rows = db.execute("SELECT hour, blocked, allowed, cached, failed FROM hourly WHERE hour >= ?",
                              (int(start.timestamp() // 3600),)).fetchall()
            first_day = start.strftime("%Y-%m-%d")
            top = db.execute("SELECT domain, SUM(blocked) FROM domains WHERE day >= ? GROUP BY domain "
                             "ORDER BY 2 DESC, 1 LIMIT 10", (first_day,)).fetchall()
            by_list = db.execute("SELECT list, SUM(blocked) FROM lists WHERE day >= ? GROUP BY list "
                                 "ORDER BY 2 DESC, 1", (first_day,)).fetchall()

        if unit == "hour":
            starts = [start + datetime.timedelta(hours=i) for i in range(count)]
        elif unit == "day":
            starts = [start + datetime.timedelta(days=i) for i in range(count)]
        else:
            starts = [_add_months(start, i) for i in range(count)]
        slot = {s: i for i, s in enumerate(starts)}
        series = [[s, 0, 0] for s in starts]  # bucket start, blocked, lookups
        blocked = allowed = cached = failed = 0
        for hour, b, a, c, f in rows:
            i = slot.get(_bucket_start(datetime.datetime.fromtimestamp(hour * 3600), unit))
            if i is not None:
                series[i][1] += b
                series[i][2] += b + a + f
            blocked, allowed, cached, failed = blocked + b, allowed + a, cached + c, failed + f
        if period == "all":  # what the old stats.json had counted before this history began
            blocked += self._baseline[0]
            allowed += self._baseline[1]
        return {"unit": unit, "series": series, "blocked": blocked, "allowed": allowed,
                "cached": cached, "lookups": blocked + allowed + failed, "top": top,
                "lists": by_list, "since": datetime.datetime.fromtimestamp(self._since)}


stats = Stats()


def start_new_session():
    """Reset only session counters; the all-time history keeps going."""
    stats.new_session()


# ----- cache (works on raw messages: parsing each answer with dnslib would cost more than the
# cache saves) -----
def _skip_name(msg, off):
    """Offset just past the (possibly compressed) domain name starting at off."""
    while True:
        length = msg[off]
        if length == 0:
            return off + 1
        if length >= 0xC0:  # compression pointer: the rest of the name is elsewhere
            return off + 2
        if length > 63:
            raise ValueError("bad label")
        off += 1 + length


def _ttl_fields(msg):
    """(offsets of every record's TTL except OPT's, smallest TTL in the answer and authority
    sections or None). Raises on a malformed message."""
    qd, an, ns, ar = struct.unpack_from("!4H", msg, 4)
    off = 12
    for _ in range(qd):
        off = _skip_name(msg, off) + 4
    offsets, smallest = [], None
    for i in range(an + ns + ar):
        off = _skip_name(msg, off)
        rtype, _, ttl, rdlen = struct.unpack_from("!HHIH", msg, off)
        if rtype != QTYPE.OPT:  # OPT's "TTL" holds EDNS flags
            offsets.append(off + 4)
            if i < an + ns:
                smallest = ttl if smallest is None else min(smallest, ttl)
        off += 10 + rdlen
    if off > len(msg):
        raise ValueError("truncated message")
    return offsets, smallest


def _cache_key(request):
    """What an answer depends on: the question, plus the DNSSEC flags (DO, CD) that change it."""
    dnssec_ok = any(rr.rtype == QTYPE.OPT and rr.ttl & 0x8000 for rr in request.ar)
    q = request.q
    return str(q.qname).lower(), q.qtype, q.qclass, dnssec_ok, request.header.cd


class _Cache:
    """Upstream answers, served with their TTLs counted down. An answer up to STALE_FOR seconds
    past its TTL still goes out (with a 30-second TTL) while a fresh one is fetched."""

    def __init__(self):
        self._entries = collections.OrderedDict()  # key -> (answer, ttl offsets, ttls, stored, ttl)
        self._lock = threading.Lock()

    def get(self, key, query):
        """(answer to query, whether it's stale), or (None, False) if there's nothing usable."""
        with self._lock:
            entry = self._entries.get(key)
            if entry is not None:
                self._entries.move_to_end(key)
        if entry is None:
            return None, False
        answer, offsets, ttls, stored, ttl = entry
        age = int(time.monotonic() - stored)
        if age >= ttl + STALE_FOR:
            return None, False
        stale = age >= ttl
        out = bytearray(answer)
        for off, record_ttl in zip(offsets, ttls):
            struct.pack_into("!I", out, off, STALE_TTL if stale else max(record_ttl - age, 1))
        qend = _skip_name(query, 12) + 4
        out[:2] = query[:2]            # this query's ID
        out[12:qend] = query[12:qend]  # and its question, in the letter case it used
        return bytes(out), stale

    def put(self, key, query, answer):
        try:
            if answer[2] & 0x02 or (answer[3] & 0x0F) not in (RCODE.NOERROR, RCODE.NXDOMAIN):
                return  # truncated, or an error that's worth asking about again
            qend = _skip_name(query, 12) + 4
            if (query[4:6] != b"\x00\x01" or answer[4:6] != b"\x00\x01"
                    or answer[12:qend - 4].lower() != query[12:qend - 4].lower()
                    or answer[qend - 4:qend] != query[qend - 4:qend]):
                return  # not an answer to exactly this one question
            offsets, ttl = _ttl_fields(answer)
        except (IndexError, ValueError, struct.error):
            return
        if not ttl:
            return  # TTL 0, or nothing to take a TTL from (a negative answer without an SOA)
        ttls = [struct.unpack_from("!I", answer, off)[0] for off in offsets]
        with self._lock:
            self._entries[key] = (answer, offsets, ttls, time.monotonic(), min(ttl, MAX_TTL))
            self._entries.move_to_end(key)
            while len(self._entries) > CACHE_SIZE:
                self._entries.popitem(last=False)

    def clear(self):
        with self._lock:
            self._entries.clear()


# ----- upstreams -----
_FETCH = ThreadPoolExecutor(max_workers=64, thread_name_prefix="doh")      # upstream requests
_REFRESH = ThreadPoolExecutor(max_workers=4, thread_name_prefix="refresh")  # stale cache entries


class _DohUpstream:
    def __init__(self, name, ip, hostname):
        self.name, self.ip, self.hostname = name, ip, hostname
        self.down_until = 0.0
        self.failures = 0
        self.srtt = None  # smoothed response time, seconds
        self.headers = {"Host": hostname, "Content-Type": "application/dns-message",
                        "Accept": "application/dns-message"}
        self._lock = threading.Lock()
        self.pool = self._new_pool()

    def _new_pool(self):
        # Kept-alive connections: one TLS handshake, then each query is a single round trip.
        return urllib3.HTTPSConnectionPool(
            self.ip, 443, server_hostname=self.hostname, ssl_context=_SSL_CONTEXT,
            maxsize=16, block=False, retries=False,
            timeout=urllib3.Timeout(connect=2.0, read=3.0),
        )

    def query(self, wire):
        for attempt in range(2):
            started = time.monotonic()
            try:
                resp = self.pool.request("POST", "/dns-query", body=wire, headers=self.headers)
                break
            except (urllib3.exceptions.ProtocolError, urllib3.exceptions.ClosedPoolError):
                # A kept-alive connection the other end had already closed. The rest of the pool
                # is probably just as old, so start over with fresh connections, once.
                if attempt:
                    raise
                self.reset()
        if resp.status != 200 or not resp.data:
            raise _HttpError(resp.status)
        took = time.monotonic() - started
        self.srtt = took if self.srtt is None else 0.8 * self.srtt + 0.2 * took
        return resp.data

    def reset(self):
        """Drop pooled connections; they go stale when the network or VPN changes."""
        with self._lock:
            old, self.pool = self.pool, self._new_pool()
        old.close()


class _HttpError(Exception):
    def __init__(self, status):
        super().__init__(f"HTTP {status}")
        self.status = status


def _udp_query(server, wire, timeout=2.0):
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.connect((server, 53))
        s.send(wire)
        while True:
            data = s.recv(65535)
            if data[:2] == wire[:2]:  # matching query ID
                return data


def _scutil_show(key):
    try:
        return subprocess.run(["/usr/sbin/scutil"], input=f"show {key}\n",
                              capture_output=True, text=True, timeout=3).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def network_dns_servers():
    """DNS servers the current network handed out (DHCP/router advertisement). Read from
    macOS's live state, which keeps them even while our 127.0.0.1 override is in place.
    Loopback addresses (this shield, Mullvad's local resolver) are skipped to avoid loops."""
    m = re.search(r"PrimaryService : (\S+)", _scutil_show("State:/Network/Global/IPv4"))
    if not m:
        return []
    servers = []
    for addr in re.findall(r"^\s*\d+ : (\S+)$", _scutil_show(f"State:/Network/Service/{m.group(1)}/DNS"), re.M):
        try:
            if not ipaddress.ip_address(addr.split("%")[0]).is_loopback:
                servers.append(addr)
        except ValueError:
            pass  # a search domain, not an address
    return servers


class Upstreams:
    def __init__(self):
        self.doh = [_DohUpstream(*u) for u in DOH_UPSTREAMS]
        self.last_used = None  # description of whoever answered last, for the UI
        self._network = ([], 0.0)
        self._route = self._current_route()

    def _current_route(self):
        """The local address the system would use to reach our first upstream."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect((self.doh[0].ip, 443))  # only picks a route; nothing is sent
                return s.getsockname()[0]
        except OSError:
            return None

    def check_network(self):
        """True if the route to the internet changed (VPN connected or dropped, other Wi-Fi).
        Connections opened on the old route just go silent, and waiting for each to time out
        would stall lookups for seconds, so start over with fresh ones."""
        route = self._current_route()
        if route == self._route:
            return False
        self._route = route
        for up in self.doh:
            up.reset()
            up.down_until, up.failures, up.srtt = 0.0, 0, None
        self._network = ([], 0.0)
        return True

    def warm(self):
        """Connect to the first two upstreams now, so early lookups skip the TLS handshake."""
        wire = DNSRecord.question("cloudflare.com").pack()
        for up in self.doh[:2]:
            _FETCH.submit(self._ask, up, wire)

    def _network_servers(self):
        servers, fetched = self._network
        if time.monotonic() - fetched > 10:
            servers = network_dns_servers()
            self._network = (servers, time.monotonic())
        return servers

    def _ask(self, up, wire):
        """up's answer, or None. Takes up out of rotation for a while if it looks broken."""
        try:
            data = up.query(wire)
            up.failures = 0
            return data
        except _HttpError as e:
            if e.status < 500:
                return None  # it refused this particular query; it isn't down
            error = e
        except urllib3.exceptions.ReadTimeoutError as e:
            up.reset()  # the connection may have died without a word; don't reuse it
            up.failures += 1
            if up.failures < 2:
                return None  # one slow answer isn't enough to write it off
            error = e
        except Exception as e:
            error = e
        print(f"[!] {up.name} {up.ip} failed ({error}); skipping it for {UPSTREAM_COOLDOWN}s")
        up.down_until = time.monotonic() + UPSTREAM_COOLDOWN
        up.failures = 0
        up.reset()
        return None

    def resolve(self, wire):
        """(answer, from DoH) for a raw query, or (None, False) if nobody answered. If the
        upstream we asked is slow, the next one is asked as well and the first answer wins."""
        now = time.monotonic()
        waiting = iter([up for up in self.doh if up.down_until <= now])
        pending = {}

        def ask_next():
            up = next(waiting, None)
            if up is not None:
                pending[_FETCH.submit(self._ask, up, wire)] = up
            return up

        first = ask_next()
        hedge = min(1.0, max(HEDGE_MIN, 3 * (first.srtt or 0))) if first else 0
        while pending:
            done, _ = wait(pending, timeout=hedge, return_when=FIRST_COMPLETED)
            for future in done:
                up = pending.pop(future)
                data = future.result()
                if data is not None:
                    self.last_used = f"{up.name} (DNS-over-HTTPS)"
                    return data, True
            if not done or not pending:
                ask_next()  # too slow, or everyone asked so far failed: bring in the next one

        if FALLBACK_TO_NETWORK_DNS:
            for server in self._network_servers():
                try:
                    data = _udp_query(server, wire)
                    self.last_used = f"network DNS {server} (fallback, not encrypted)"
                    return data, False
                except OSError as e:
                    print(f"[!] Network DNS {server} failed: {e}")
        return None, False


# ----- server -----
def _reply(request, rcode=RCODE.NOERROR):
    reply = request.reply()
    reply.header.rcode = rcode
    reply.header.ad = 0  # reply() copies the query's flags; we never DNSSEC-validate
    return reply


def _blocked_reply(request):
    reply = _reply(request)
    qname, qtype = request.q.qname, request.q.qtype
    if qtype == QTYPE.A:
        reply.add_answer(RR(qname, QTYPE.A, rdata=A("0.0.0.0"), ttl=BLOCK_TTL))
    elif qtype == QTYPE.AAAA:
        reply.add_answer(RR(qname, QTYPE.AAAA, rdata=AAAA("::"), ttl=BLOCK_TTL))
    return reply  # any other type gets an empty answer


def _udp_limit(request):
    for rr in request.ar:
        if rr.rtype == QTYPE.OPT:  # EDNS0: the client's UDP buffer size is in the class field
            return max(512, rr.rclass)
    return 512


def _recv_exact(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _mtime(path):
    try:
        return os.stat(path).st_mtime
    except OSError:
        return None


class ShieldServer:
    """Serves DNS on already-bound UDP and TCP sockets until stop() is called."""

    def __init__(self, udp_sock, tcp_sock, blocklists, whitelist=None, blacklist=None):
        """blocklists is {name: path}; the name is what the stats credit a block to."""
        self.udp, self.tcp = udp_sock, tcp_sock
        self.blocklists = dict(blocklists)
        self.whitelist_path = whitelist or WHITELIST_FILE
        self.blacklist_path = blacklist or BLACKLIST_FILE
        self.blocked = {}  # domain -> name of the first list that has it
        self.allowed, self.denied = set(), set()
        self.upstreams = Upstreams()
        self.cache = _Cache()
        self._mtimes = {}
        self._refreshing = set()
        self._refresh_lock = threading.Lock()
        self._stop = threading.Event()
        self._threads = []
        self._pool = None

    def start(self):
        self._reload_user_lists()
        blocked = {}
        for name, path in self.blocklists.items():
            for domain in load_blocklist(path):
                blocked.setdefault(domain, name)
        self.blocked = blocked
        print(f"[+] Loaded {len(self.blocked)} blocked, {len(self.denied)} blacklisted and "
              f"{len(self.allowed)} whitelisted domains")

        self._stop.clear()
        self._pool = ThreadPoolExecutor(max_workers=WORKERS, thread_name_prefix="dns")
        for sock in (self.udp, self.tcp):
            sock.settimeout(0.5)  # lets the loops notice stop()
        self._threads = [threading.Thread(target=t, daemon=True)
                         for t in (self._udp_loop, self._tcp_loop, self._housekeeping)]
        for t in self._threads:
            t.start()
        self.upstreams.warm()

    def stop(self):
        self._stop.set()
        for t in self._threads:
            t.join(timeout=2)
        self._threads = []
        if self._pool:
            self._pool.shutdown(wait=False, cancel_futures=True)
        stats.flush()

    def _reload_user_lists(self):
        """Load your whitelist and blacklist if they changed on disk. True if either did."""
        changed = False
        for attr, path in (("allowed", self.whitelist_path), ("denied", self.blacklist_path)):
            mtime = _mtime(path)
            if path not in self._mtimes or self._mtimes[path] != mtime:
                self._mtimes[path] = mtime
                setattr(self, attr, load_user_list(path))
                changed = True
        return changed

    def block_reason(self, qname):
        """What blocks qname (BLACKLIST_NAME or a blocklist's name), or None if nothing does.
        Your blacklist and whitelist beat the blocklists. Between those two the more specific
        entry wins (whitelisted example.com plus blacklisted ads.example.com blocks just ads.),
        and a tie goes to the whitelist."""
        allow = _match(qname, self.allowed)
        deny = _match(qname, self.denied)
        if deny and (not allow or len(deny) > len(allow)):
            return BLACKLIST_NAME
        if allow:
            return None
        hit = _match(qname, self.blocked)
        return self.blocked[hit] if hit else None

    def local_answer(self, request):
        """The response if no upstream is needed (blocked, local-only, malformed), else None."""
        if request.header.opcode != 0:
            return _reply(request, RCODE.NOTIMP).pack()
        if not request.questions:
            return _reply(request, RCODE.FORMERR).pack()
        qname = str(request.q.qname).rstrip(".").lower()
        if _local_only(qname):
            return _reply(request, RCODE.NXDOMAIN).pack()
        reason = self.block_reason(qname)
        if reason:
            stats.record(blocked=True, name=qname, source=reason)
            return _blocked_reply(request).pack()
        return None

    def cached_answer(self, request, wire):
        """A cached upstream answer, or None. A stale one is refreshed in the background."""
        key = _cache_key(request)
        resp, stale = self.cache.get(key, wire)
        if resp is None:
            return None
        if stale:
            self._refresh(key, wire)
        stats.record(blocked=False, cached=True)
        return resp

    def forward(self, request, wire):
        """Ask upstream (the query goes out as-is) and cache the answer."""
        resp, cacheable = self.upstreams.resolve(wire)
        if resp is None:
            stats.record_failure()
            return _reply(request, RCODE.SERVFAIL).pack()
        if cacheable:
            self.cache.put(_cache_key(request), wire, resp)
        stats.record(blocked=False)
        return resp

    def answer(self, request, wire):
        """Response bytes for one parsed query (wire is the raw query)."""
        return (self.local_answer(request) or self.cached_answer(request, wire)
                or self.forward(request, wire))

    def _refresh(self, key, wire):
        with self._refresh_lock:
            if key in self._refreshing:
                return
            self._refreshing.add(key)

        def fetch():
            try:
                resp, cacheable = self.upstreams.resolve(wire)
                if resp is not None and cacheable:
                    self.cache.put(key, wire, resp)
            finally:
                with self._refresh_lock:
                    self._refreshing.discard(key)

        _REFRESH.submit(fetch)

    def _udp_loop(self):
        while not self._stop.is_set():
            try:
                data, addr = self.udp.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError as e:
                if not self._stop.is_set():
                    print(f"[!] UDP receive failed: {e}")
                    time.sleep(0.2)
                continue
            if addr is None:  # the socket was shut down under us; don't spin
                print("[!] The DNS socket was closed; the shield stopped answering")
                return
            try:
                request = DNSRecord.parse(data)
            except Exception:
                continue  # not a DNS message
            try:
                resp = self.local_answer(request)
            except Exception as e:  # never let a bug here wave a blocked name through
                print(f"[!] Error checking {request.q.qname}: {e}")
                resp = _reply(request, RCODE.SERVFAIL).pack()
            if resp is None:
                try:
                    resp = self.cached_answer(request, data)
                except Exception as e:
                    print(f"[!] Cache error for {request.q.qname}: {e}")
            # Blocked, local and cached names are answered right here, so they (and the helper's
            # liveness check) never wait behind slow upstream lookups in the worker queue.
            if resp is None:
                self._pool.submit(self._forward_udp, request, data, addr)
            else:
                self._send_udp(request, resp, addr)

    def _forward_udp(self, request, data, addr):
        try:
            resp = self.forward(request, data)
        except Exception as e:
            print(f"[!] Error answering {request.q.qname}: {e}")
            resp = _reply(request, RCODE.SERVFAIL).pack()
        self._send_udp(request, resp, addr)

    def _send_udp(self, request, resp, addr):
        if len(resp) > _udp_limit(request):
            truncated = _reply(request)
            truncated.header.tc = 1  # client retries over TCP
            resp = truncated.pack()
        try:
            self.udp.sendto(resp, addr)
        except OSError:
            pass

    def _tcp_loop(self):
        while not self._stop.is_set():
            try:
                conn, _ = self.tcp.accept()
            except socket.timeout:
                continue
            except OSError as e:
                if not self._stop.is_set():
                    print(f"[!] TCP accept failed: {e}")
                    time.sleep(0.2)
                continue
            threading.Thread(target=self._serve_tcp, args=(conn,), daemon=True).start()

    def _serve_tcp(self, conn):
        with conn:
            conn.settimeout(10)
            try:
                while not self._stop.is_set():
                    header = _recv_exact(conn, 2)
                    data = header and _recv_exact(conn, struct.unpack("!H", header)[0])
                    if not data:
                        return
                    request = DNSRecord.parse(data)
                    resp = self.answer(request, data)
                    conn.sendall(struct.pack("!H", len(resp)) + resp)
            except Exception:
                return  # client went away or sent garbage

    def _housekeeping(self):
        while not self._stop.wait(1):
            stats.flush()
            if self._reload_user_lists():
                print(f"[+] Reloaded your lists: {len(self.denied)} blacklisted, "
                      f"{len(self.allowed)} whitelisted")
            if self.upstreams.check_network():
                self.cache.clear()
                print("[+] Network changed; reconnected to the upstreams and cleared the cache")


def lookup(name, port=53, timeout=10.0):
    """IPv4 addresses the shield on 127.0.0.1:port gives for name, or None if it didn't answer
    normally."""
    query = DNSRecord.question(name, "A")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(query.pack(), ("127.0.0.1", port))
            reply = DNSRecord.parse(s.recv(65535))
    except Exception:
        return None
    if reply.header.id != query.header.id or reply.header.rcode != RCODE.NOERROR:
        return None
    return [str(rr.rdata) for rr in reply.rr if rr.rtype == QTYPE.A]


def probe(port=53, name="example.com", timeout=10.0):
    """True if the shield on 127.0.0.1:port resolves a real name."""
    return bool(lookup(name, port, timeout))


def bind_sockets(port, host="127.0.0.1"):
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        udp.bind((host, port))
        tcp.bind((host, port))
        tcp.listen(64)
    except OSError:
        udp.close()
        tcp.close()
        raise
    return udp, tcp


def main():
    parser = argparse.ArgumentParser(description="Run the DNS filter by itself (for testing).")
    parser.add_argument("--port", type=int, default=5300)
    parser.add_argument("--lists", nargs="*", default=["moderate"],
                        help=f"blocklists to use: {', '.join(available_blocklists())}")
    args = parser.parse_args()
    lists = {name: blocklist_path(name) for name in args.lists}
    if None in lists.values():
        parser.error(f"unknown list; choose from {', '.join(available_blocklists())}")

    udp, tcp = bind_sockets(args.port)
    server = ShieldServer(udp, tcp, lists)
    server.start()
    print(f"[+] Listening on 127.0.0.1:{args.port}. Try: dig @127.0.0.1 -p {args.port} example.com")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()


if __name__ == "__main__":
    main()
