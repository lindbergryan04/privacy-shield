#!/usr/bin/env python3
"""Privacy Shield's privileged helper. This is the only part that runs as root.

app.py starts it through the macOS administrator prompt. It:
  1. binds 127.0.0.1:53 (UDP and TCP) and hands the sockets to the app, which does all the DNS
     work without root;
  2. on "apply", points DNS at 127.0.0.1: every enabled network service (networksetup) and, if
     Mullvad is installed, Mullvad's custom DNS. While Mullvad is connected it overrides system
     DNS and forwards to its custom DNS server, so that second setting is what keeps the shield
     in the path;
  3. on "restore", puts both back the way they were.

It also restores when the app quits, crashes or is force-quit (the connection closes), on
SIGTERM/SIGINT, and if the shield stops answering queries. The original settings are written to
~/Library/Application Support/PrivacyShield/state.json before anything changes, so if a session
is never cleaned up (power loss, kill -9) this puts things back:

    sudo python3 shield_helper.py --restore

Standard library only, so that command works even if the venv is broken.
"""
import argparse, ipaddress, json, os, pwd, select, signal, socket, subprocess, sys, time

STATE_FILE = None  # set in main(): state.json in the owner's ~/Library/Application Support/PrivacyShield
LOCAL_DNS = "127.0.0.1"
NETWORKSETUP = "/usr/sbin/networksetup"
MULLVAD_PATHS = [
    "/usr/local/bin/mullvad",
    "/Applications/Mullvad VPN.app/Contents/Resources/mullvad",
    "/opt/homebrew/bin/mullvad",
]
# "mullvad dns get" labels -> the "mullvad dns set default" flags that turn them back on
MULLVAD_BLOCKERS = {
    "Block ads": "--block-ads",
    "Block trackers": "--block-trackers",
    "Block malware": "--block-malware",
    "Block adult content": "--block-adult-content",
    "Block gambling": "--block-gambling",
    "Block social media": "--block-social-media",
}
WATCHDOG_INTERVAL = 10  # seconds between checks that the shield still answers
WATCHDOG_MISSES = 3     # restore DNS after this many checks in a row get no answer

dry_run = False  # --dry-run: print commands that would change settings instead of running them


def log(msg):
    print(f"[helper {time.strftime('%H:%M:%S')}] {msg}", flush=True)


def run(cmd, change=False):
    """Run a command and return its stdout. Commands that change settings are only printed
    under --dry-run."""
    if change and dry_run:
        log("dry run, would run: " + " ".join(cmd))
        return ""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as e:  # missing binary, hung command
        raise RuntimeError(f"{' '.join(cmd)} failed: {e}")
    if r.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} failed: {(r.stderr or r.stdout).strip()}")
    return r.stdout


def _ips(text):
    out = []
    for line in text.splitlines():
        try:
            out.append(str(ipaddress.ip_address(line.strip())))
        except ValueError:
            pass
    return out


# ----- macOS network services -----
def network_services():
    """Enabled network services, e.g. ["Wi-Fi", "USB 10/100/1000 LAN"]."""
    lines = run([NETWORKSETUP, "-listallnetworkservices"]).splitlines()[1:]  # line 1 is a note
    return [s for s in lines if s.strip() and not s.startswith("*")]  # * = disabled


def get_dns(service):
    """Manually set DNS servers for a service. [] means automatic (from DHCP)."""
    return _ips(run([NETWORKSETUP, "-getdnsservers", service]))


def set_dns(service, servers):
    try:
        run([NETWORKSETUP, "-setdnsservers", service, *(servers or ["Empty"])], change=True)
    except RuntimeError as e:
        if "not a recognized network service" not in str(e):
            raise  # a service deleted since then has nothing to restore


# ----- Mullvad -----
def mullvad_cli():
    return next((p for p in MULLVAD_PATHS if os.path.exists(p)), None)


def get_mullvad_dns(cli):
    """Mullvad's DNS setting as {"custom": bool, "servers": [...], "flags": [...]}."""
    out = run([cli, "dns", "get"])
    if "Custom DNS: yes" in out:
        return {"custom": True, "servers": _ips(out), "flags": []}
    lines = {line.strip() for line in out.splitlines()}
    flags = [flag for label, flag in MULLVAD_BLOCKERS.items() if f"{label}: true" in lines]
    return {"custom": False, "servers": [], "flags": flags}


def set_mullvad_dns(cli, setting):
    if setting["custom"] and setting["servers"]:
        run([cli, "dns", "set", "custom", *setting["servers"]], change=True)
    else:
        run([cli, "dns", "set", "default", *setting["flags"]], change=True)


# ----- saved state -----
def load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except FileNotFoundError:
        return None
    except ValueError:
        log(f"{STATE_FILE} is unreadable; ignoring it")
        return None


def save_state(state, owner_uid):
    folder = os.path.dirname(STATE_FILE)
    if not os.path.isdir(folder):
        os.makedirs(folder)
        os.chown(folder, owner_uid, -1)
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f, indent=2)
    os.chown(tmp, owner_uid, -1)  # so the app (not root) can read and delete it
    os.replace(tmp, STATE_FILE)


def capture_state(owner_uid):
    """Record the settings to put back later. Settings saved by an earlier session that never
    restored win over the live ones, which would just be our own 127.0.0.1 by then."""
    state = load_state() or {"version": 1, "saved_at": time.time(), "services": {}, "mullvad": None}
    if state["services"]:
        log("Reusing original settings saved by an earlier session")
    for service in network_services():
        if service not in state["services"]:
            current = get_dns(service)
            state["services"][service] = [] if current == [LOCAL_DNS] else current
    cli = mullvad_cli()
    if cli and state.get("mullvad") is None:
        try:
            setting = get_mullvad_dns(cli)
        except RuntimeError as e:
            log(f"Mullvad is installed but its CLI failed ({e}); leaving Mullvad alone")
        else:
            if setting["custom"] and setting["servers"] == [LOCAL_DNS]:
                setting = {"custom": False, "servers": [], "flags": []}
            state["mullvad"] = setting
    save_state(state, owner_uid)
    return state


# ----- apply / restore -----
def flush_dns_cache():
    for cmd in (["/usr/bin/dscacheutil", "-flushcache"], ["/usr/bin/killall", "-HUP", "mDNSResponder"]):
        try:
            run(cmd, change=True)
        except (RuntimeError, OSError, subprocess.SubprocessError):
            pass


def remove_old_pf_rules():
    """v0.1 redirected port 53 with pf rules in this anchor. Leftovers would hijack our
    queries, so clear them. Only touches this one anchor."""
    try:
        run(["/sbin/pfctl", "-a", "com.apple/PrivacyShield", "-F", "all"], change=True)
    except (RuntimeError, OSError, subprocess.SubprocessError):
        pass


def apply(state):
    """Point system DNS and Mullvad at the shield. Returns a summary for the app."""
    remove_old_pf_rules()
    services, errors = [], []
    for service in state["services"]:
        try:
            set_dns(service, [LOCAL_DNS])
            services.append(service)
        except RuntimeError as e:
            errors.append(str(e))
    mullvad = "not installed"
    cli = mullvad_cli()
    if cli and state.get("mullvad") is not None:
        try:
            run([cli, "dns", "set", "custom", LOCAL_DNS], change=True)
            mullvad = "custom DNS set to 127.0.0.1"
        except RuntimeError as e:
            errors.append(str(e))
            mullvad = "couldn't change its DNS setting"
    elif cli:
        mullvad = "CLI not responding"
    flush_dns_cache()
    for e in errors:
        log(e)
    log(f"Applied: services={services} mullvad={mullvad}")
    return {"ok": bool(services), "services": services, "mullvad": mullvad, "errors": errors}


def restore(state):
    """Put back the saved settings. Returns a list of errors (empty on success)."""
    errors = []
    for service, servers in state.get("services", {}).items():
        try:
            set_dns(service, servers)
        except RuntimeError as e:
            errors.append(str(e))
    cli = mullvad_cli()
    if state.get("mullvad"):
        try:
            if not cli:
                raise RuntimeError("Mullvad CLI not found")
            set_mullvad_dns(cli, state["mullvad"])
        except RuntimeError as e:
            errors.append(str(e))
    flush_dns_cache()
    if errors:
        for e in errors:
            log(e)
        log(f"Kept {STATE_FILE} so a later restore can finish the job")
    else:
        log("Restored original DNS settings")
        if os.path.exists(STATE_FILE):
            os.remove(STATE_FILE)
    return errors


def restore_leftovers():
    """--restore: undo a session that never cleaned up. Without a state file, reset anything
    still pointing at 127.0.0.1 (nothing answers there once the app is gone)."""
    state = load_state()
    if state is None:
        state = {"services": {s: [] for s in network_services() if get_dns(s) == [LOCAL_DNS]},
                 "mullvad": None}
        cli = mullvad_cli()
        if cli:
            try:
                setting = get_mullvad_dns(cli)
                if setting["custom"] and setting["servers"] == [LOCAL_DNS]:
                    state["mullvad"] = {"custom": False, "servers": [], "flags": []}
            except RuntimeError as e:
                log(f"Couldn't read Mullvad's DNS setting: {e}")
        if not state["services"] and not state["mullvad"]:
            log("Nothing to restore: no saved settings and nothing points at 127.0.0.1")
            return []
    log(f"Restoring: {state}")
    return restore(state)


# ----- session with the app -----
def shield_answers(port):
    """True if something answers DNS on 127.0.0.1:port. Asks for a single-label name, which the
    shield answers itself, so a slow upstream doesn't count as the shield being down."""
    qid = os.urandom(2)
    msg = (qid + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
           + b"\x14privacy-shield-check\x00" + b"\x00\x01\x00\x01")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(3)
        try:
            s.sendto(msg, ("127.0.0.1", port))
            return s.recv(512)[:2] == qid
        except OSError:
            return False


def bind_sockets(port):
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp.bind((LOCAL_DNS, port))
    tcp.bind((LOCAL_DNS, port))
    tcp.listen(64)
    return udp, tcp


def session(sock_path, owner_uid, port):
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    conn.connect(sock_path)

    def send(msg, fds=()):
        data = json.dumps(msg).encode() + b"\n"
        if fds:
            socket.send_fds(conn, [data], list(fds))
        else:
            conn.sendall(data)

    try:
        udp, tcp = bind_sockets(port)
    except OSError as e:
        send({"event": "error", "message": f"Couldn't listen on {LOCAL_DNS}:{port}: {e}. Is "
                                            "another copy of Privacy Shield (or another DNS "
                                            "tool) running?"})
        return
    send({"event": "hello", "port": port, "pid": os.getpid()}, [udp.fileno(), tcp.fileno()])
    # Keep our copies open for the whole session. If these were the only references left while
    # the sockets are in transit, closing any unix socket can make macOS's in-flight descriptor
    # garbage collector decide they're orphaned and shut them down before the app reads them.

    state, buf, misses = None, b"", 0
    try:
        while True:
            ready, _, _ = select.select([conn], [], [], WATCHDOG_INTERVAL)
            if not ready:
                if state is not None:
                    misses = 0 if shield_answers(port) else misses + 1
                    if misses >= WATCHDOG_MISSES:
                        log("The shield stopped answering queries; restoring DNS so you stay online")
                        restore(state)
                        state = None
                        send({"event": "restored", "reason": "Privacy Shield stopped answering DNS "
                                                             "queries, so your normal DNS was put back."})
                continue
            chunk = conn.recv(4096)
            if not chunk:
                log("App went away")
                break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                cmd = json.loads(line).get("cmd")
                if cmd == "quit":
                    return
                try:
                    if cmd == "apply":
                        state = capture_state(owner_uid)
                        misses = 0
                        send({"reply": "apply", **apply(state)})
                    elif cmd == "restore":
                        # Nothing applied by this helper: clean up after one that died instead
                        errors = restore(state) if state is not None else restore_leftovers()
                        state = None
                        send({"reply": "restore", "ok": not errors, "errors": errors})
                except (RuntimeError, OSError) as e:
                    log(f"{cmd} failed: {e}")
                    send({"reply": cmd, "ok": False, "errors": [str(e)]})
    finally:
        # Don't let a second signal (say, SIGTERM at shutdown) cut the restore short.
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        if state is not None:
            restore(state)
        udp.close()
        tcp.close()
        log("Exiting")


def main():
    global dry_run, STATE_FILE
    ap = argparse.ArgumentParser(description="Privileged helper for Privacy Shield (runs as root).")
    ap.add_argument("--connect", metavar="SOCKET", help="the app's unix socket (app.py passes this)")
    ap.add_argument("--owner-uid", type=int, default=int(os.environ.get("SUDO_UID", os.getuid())))
    ap.add_argument("--port", type=int, default=53)
    ap.add_argument("--restore", action="store_true",
                    help="put back DNS settings from a session that didn't clean up")
    ap.add_argument("--dry-run", action="store_true",
                    help="print commands that would change settings instead of running them")
    args = ap.parse_args()

    dry_run = args.dry_run
    home = pwd.getpwuid(args.owner_uid).pw_dir
    STATE_FILE = os.path.join(home, "Library", "Application Support", "PrivacyShield",
                              "state.dry-run.json" if dry_run else "state.json")
    if not dry_run and os.geteuid() != 0:
        sys.exit("This needs root. Run it with sudo.")

    if args.restore:
        sys.exit(1 if restore_leftovers() else 0)
    if not args.connect:
        ap.error("--connect or --restore is required")

    def _exit(signum, frame):
        raise SystemExit(0)  # unwinds through session()'s finally, which restores DNS

    signal.signal(signal.SIGTERM, _exit)
    signal.signal(signal.SIGINT, _exit)
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    log(f"Started (pid {os.getpid()}, port {args.port}{', dry run' if dry_run else ''})")
    session(args.connect, args.owner_uid, args.port)


if __name__ == "__main__":
    main()
