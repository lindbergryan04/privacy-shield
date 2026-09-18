import sys, fcntl, json, os, queue, re, shlex, shutil, signal, socket, subprocess, tempfile, threading, time, traceback
from urllib.parse import urlsplit
from PyQt5.QtWidgets import (
    QApplication,
    QWidget,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QVBoxLayout,
    QPushButton,
    QComboBox,
    QStyledItemDelegate,
)
from PyQt5.QtCore import Qt, QEvent, QTimer, QObject, QSettings, pyqtSignal
import analytics
import dns_proxy

HELPER = os.path.join(dns_proxy.BASE_DIR, "shield_helper.py")
# Outside ~/Desktop on purpose: macOS privacy protection can stop the root helper from reading
# or writing files there.
HELPER_LOG = os.path.expanduser("~/Library/Logs/PrivacyShield/helper.log")
APP_LOG = os.path.expanduser("~/Library/Logs/PrivacyShield/app.log")  # built app only
STATE_FILE = os.path.expanduser("~/Library/Application Support/PrivacyShield/state.json")
MULLVAD_PATHS = ["/usr/local/bin/mullvad", "/Applications/Mullvad VPN.app/Contents/Resources/mullvad"]
LIST_ORDER = ["Strict", "Moderate", "Permissive", "Streaming", "Social", "Adult"]

# PRIVACY_SHIELD_DRY_RUN=1 python app.py: try the app without a password prompt or any settings
# changes. The helper runs as you on port 5300 and only prints what it would change.
DRY_RUN = os.environ.get("PRIVACY_SHIELD_DRY_RUN") == "1"


class HelperError(Exception):
    pass


class HelperConnection:
    """Talks to shield_helper.py, the part that runs as root (see the top of that file)."""

    def __init__(self, on_event):
        self.on_event = on_event  # called on the reader thread for messages that aren't replies
        self.conn = None
        self.port = None
        self.sockets = None  # (udp, tcp) bound to 127.0.0.1:53 by the helper
        self._replies = queue.Queue()
        self._lock = threading.Lock()

    @property
    def connected(self):
        return self.conn is not None

    def launch(self, timeout=300):
        """Start the helper (macOS asks for an administrator password) and wait for it to connect.
        The socket lives in a fresh private directory, so only you and root can reach it."""
        # A previous helper's port-53 sockets would stop the new one from binding the port.
        for sock in self.sockets or ():
            sock.close()
        self.sockets = None
        run_dir = tempfile.mkdtemp(prefix="privacy-shield-", dir="/tmp")
        sock_path = os.path.join(run_dir, "helper.sock")
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            listener.bind(sock_path)
            listener.listen(1)
            listener.settimeout(0.5)
            proc, direct = self._start_process(run_dir, sock_path)
            deadline = time.monotonic() + timeout
            while True:
                try:
                    conn, _ = listener.accept()
                    break
                except socket.timeout:
                    pass
                code = proc.poll()
                # osascript exits 0 as soon as the helper is launched in the background
                if code is not None and (code != 0 or direct):
                    err = (proc.stderr.read() if proc.stderr else "") or ""
                    if "-128" in err:
                        raise HelperError("The administrator password prompt was cancelled.")
                    raise HelperError(f"The helper didn't start: {err.strip() or f'exit code {code}'}. "
                                      f"See {HELPER_LOG}")
                if time.monotonic() > deadline:
                    raise HelperError(f"Timed out waiting for the helper. See {HELPER_LOG}")
            # Take the sockets before closing anything: closing a unix socket while descriptors
            # are in transit can get them shut down by macOS (see shield_helper.session).
            conn.settimeout(15)
            msg, fds, _, _ = socket.recv_fds(conn, 65536, 2)
            conn.settimeout(None)
        finally:
            listener.close()
            shutil.rmtree(run_dir, ignore_errors=True)

        hello = json.loads(msg.decode().splitlines()[0])
        if hello.get("event") != "hello" or len(fds) != 2:
            conn.close()
            for fd in fds:
                os.close(fd)
            raise HelperError(hello.get("message", "The helper sent an unexpected reply."))
        self.sockets = tuple(socket.socket(fileno=fd) for fd in fds)
        self.port = hello["port"]
        self._replies = queue.Queue()  # fresh, so nothing left over from a previous helper
        self.conn = conn
        threading.Thread(target=self._read_loop, args=(conn, self._replies), daemon=True).start()

    def _start_process(self, run_dir, sock_path):
        if dns_proxy.FROZEN:
            # Built .app: its own executable doubles as the helper (see launcher.py).
            args = [sys.executable, "--helper"]
        else:
            # The helper needs only the standard library, so run a copy from the private run dir
            # with the real interpreter (not the venv symlink under ~/Desktop). -I: isolated
            # mode, so the root process ignores PYTHONPATH and user site-packages.
            args = [os.path.realpath(sys.executable), "-I", shutil.copy(HELPER, run_dir)]
        args += ["--connect", sock_path, "--owner-uid", str(os.getuid())]
        if DRY_RUN:
            args += ["--dry-run", "--port", "5300"]
        os.makedirs(os.path.dirname(HELPER_LOG), exist_ok=True)
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        open(HELPER_LOG, "a").close()  # created as you, so the root helper only appends to it
        if DRY_RUN or os.geteuid() == 0:
            with open(HELPER_LOG, "a") as log:
                return subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT), True
        command = " ".join(shlex.quote(a) for a in args) + f" >> {shlex.quote(HELPER_LOG)} 2>&1 &"
        applescript = command.replace("\\", "\\\\").replace('"', '\\"')
        script = (f'do shell script "{applescript}" with prompt "Privacy Shield needs your permission '
                  f'to change DNS settings." with administrator privileges')
        proc = subprocess.Popen(["/usr/bin/osascript", "-e", script],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return proc, False

    def _read_loop(self, conn, replies):
        try:
            for line in conn.makefile("r"):
                msg = json.loads(line)
                if "reply" in msg:
                    replies.put(msg)
                else:
                    self.on_event(msg)
        except (OSError, ValueError):
            pass
        if self.conn is conn:
            self.conn = None
            self.on_event({"event": "gone"})
        replies.put(None)  # wakes a request() that's waiting

    def request(self, cmd, timeout=60):
        with self._lock:
            conn = self.conn
            if conn is None:
                raise HelperError("The helper isn't running.")
            try:
                conn.sendall(json.dumps({"cmd": cmd}).encode() + b"\n")
                reply = self._replies.get(timeout=timeout)
            except OSError as e:
                raise HelperError(f"Lost the connection to the helper: {e}")
            except queue.Empty:
                raise HelperError(f"The helper didn't answer '{cmd}'. See {HELPER_LOG}")
            if reply is None:
                raise HelperError(f"The helper exited. See {HELPER_LOG}")
            return reply

    def close(self):
        """Ask the helper to exit. It restores DNS on its way out if it still needs to."""
        conn, self.conn = self.conn, None
        if conn:
            try:
                conn.sendall(b'{"cmd": "quit"}\n')
            except OSError:
                pass
            conn.close()


def mullvad_status():
    """First line of `mullvad status` ("Connected", "Disconnected", ...), or None if absent."""
    cli = next((p for p in MULLVAD_PATHS if os.path.exists(p)), None)
    if not cli:
        return None
    try:
        out = subprocess.run([cli, "status"], capture_output=True, text=True, timeout=5).stdout
        return out.strip().splitlines()[0] if out.strip() else "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def helper_running():
    """True if some copy of the app has a helper running (so its session isn't abandoned)."""
    return subprocess.run(["/usr/bin/pgrep", "-f", "--", "--connect /tmp/privacy-shield-"],
                          capture_output=True).returncode == 0


def restore_command():
    """Terminal command that puts DNS back after a session that never cleaned up."""
    if dns_proxy.FROZEN:
        return f"sudo {shlex.quote(sys.executable)} --helper --restore"
    return f"sudo python3 {shlex.quote(HELPER)} --restore"


def domain_from_input(text):
    """A domain from what you typed or pasted: "Reddit.com", "https://www.reddit.com/r/x"."""
    text = text.strip()
    if "://" in text:
        text = urlsplit(text).hostname or ""
    return dns_proxy.clean_domain(text)


def _lines(path):
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return f.read().splitlines()


def set_rule(name, block):
    """Always block (blacklist) or always allow (whitelist) name, taking it off the other list.
    A running shield picks up the change within a second or two."""
    add_to, remove_from = ((dns_proxy.BLACKLIST_FILE, dns_proxy.WHITELIST_FILE) if block
                           else (dns_proxy.WHITELIST_FILE, dns_proxy.BLACKLIST_FILE))
    lines = _lines(remove_from)
    kept = [line for line in lines if line.strip().lower() != name]
    if kept != lines:
        with open(remove_from, "w") as f:
            f.write("\n".join(kept) + "\n")
    lines = _lines(add_to)
    if name not in (line.strip().lower() for line in lines):
        with open(add_to, "w") as f:
            f.write("\n".join(lines + [name]) + "\n")


def open_in_editor(path):
    if not os.path.exists(path):
        kind = "blocked" if path == dns_proxy.BLACKLIST_FILE else "allowed"
        with open(path, "w") as f:
            f.write(f"# Domains that are always {kind}, one per line (subdomains included).\n")
    subprocess.Popen(["/usr/bin/open", "-t", path])


_GENERIC_NAMES = {"hosts", "host", "list", "lists", "domains", "blocklist", "blocklists", "master",
                  "main", "raw", "adblock", "wildcard", "download", "txt"}


def suggest_list_name(source):
    """A default name for a list, from its URL or file name."""
    path = urlsplit(source).path if "://" in source else source
    for part in reversed([p for p in path.split("/") if p]):
        stem = os.path.splitext(part)[0]
        if stem.lower() not in _GENERIC_NAMES:
            break
    else:
        stem = (urlsplit(source).hostname or "") if "://" in source else ""
    return re.sub(r"[^A-Za-z0-9 ._-]+", " ", stem).strip()[:40] or "My list"


class CheckableComboBox(QComboBox):
    """Multi-select dropdown. The list stays open while you tick items; click outside it (or on
    the box again) to close it."""

    def __init__(self):
        super().__init__()
        self.setItemDelegate(QStyledItemDelegate())
        self.setEditable(True)
        self.lineEdit().setReadOnly(True)
        self.lineEdit().setPlaceholderText("Select blocklists...")
        self.lineEdit().installEventFilter(self)
        self.view().viewport().installEventFilter(self)
        self._just_closed = False

    def eventFilter(self, obj, event):
        if obj is self.lineEdit() and event.type() == QEvent.MouseButtonRelease:
            if not self._just_closed:
                self.showPopup()  # clicking the text opens the list too, not just the arrow
            return True
        if obj is self.view().viewport() and event.type() == QEvent.MouseButtonRelease:
            item = self.model().itemFromIndex(self.view().indexAt(event.pos()))
            if item is not None:
                item.setCheckState(Qt.Unchecked if item.checkState() == Qt.Checked else Qt.Checked)
                self.update_text()
            return True  # swallow the click, which would otherwise close the list
        return super().eventFilter(obj, event)

    def hidePopup(self):
        super().hidePopup()
        # The click that closes the list can land on the text too; don't let it reopen the list.
        self._just_closed = True
        QTimer.singleShot(150, lambda: setattr(self, "_just_closed", False))

    def set_items(self, names, checked):
        self.clear()
        for name in names:
            self.addItem(name)
            item = self.model().item(self.count() - 1)
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            item.setCheckState(Qt.Checked if name in checked else Qt.Unchecked)
        self.update_text()

    def update_text(self):
        self.lineEdit().setText(", ".join(self.checked_items()))

    def checked_items(self):
        return [self.itemText(i) for i in range(self.count())
                if self.model().item(i).checkState() == Qt.Checked]


class Bridge(QObject):
    """Carries results from worker threads back to the Qt thread."""
    done = pyqtSignal(str, object)       # (action, result or exception)
    helper_event = pyqtSignal(dict)
    mullvad = pyqtSignal(object)


class ListsDialog(QDialog):
    """Add, update and remove your own blocklists, from a URL or a file."""

    def __init__(self, parent):
        super().__init__(parent)
        self.setWindowTitle("Custom blocklists")
        self.resize(500, 340)
        self.bridge = Bridge()
        self.bridge.done.connect(self._finished)

        layout = QVBoxLayout(self)
        intro = QLabel("Add a hosts file, a plain list of domains, or an adblock-style (||domain^) "
                       "list. Lists from a URL are re-downloaded every week. New lists start "
                       "ticked; they take effect the next time you click Start.")
        intro.setWordWrap(True)
        layout.addWidget(intro)
        self.lists = QListWidget()
        layout.addWidget(self.lists)
        self.status = QLabel("")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        row = QHBoxLayout()
        self.buttons = []
        for text, slot in (("Add from URL…", self.add_url), ("Add file…", self.add_file),
                           ("Update", self.update_selected), ("Remove", self.remove_selected)):
            button = QPushButton(text)
            button.clicked.connect(slot)
            row.addWidget(button)
            self.buttons.append(button)
        layout.addLayout(row)
        done = QPushButton("Done")
        done.clicked.connect(self.accept)
        layout.addWidget(done, alignment=Qt.AlignRight)
        self.refresh()

    def refresh(self):
        self.lists.clear()
        for info in dns_proxy.custom_lists():
            source = (urlsplit(info["source"]).hostname if "://" in info["source"]
                      else "a file")
            count = f"{info['domains']:,} domains, " if info["domains"] is not None else ""
            updated = time.strftime("%b %-d", time.localtime(info["updated"]))
            item = QListWidgetItem(f"{info['name']}  ({count}from {source}, updated {updated})")
            item.setData(Qt.UserRole, info["name"])
            self.lists.addItem(item)
        if not self.lists.count():
            self.status.setText("You haven't added any lists yet.")

    def _selected(self):
        item = self.lists.currentItem()
        if item is None:
            self.status.setText("Select a list first.")
            return None
        return item.data(Qt.UserRole)

    def _run(self, message, fn):
        self.status.setText(message)
        for button in self.buttons:
            button.setDisabled(True)

        def work():
            try:
                result = fn()
            except Exception as e:
                result = e
            self.bridge.done.emit("list", result)

        threading.Thread(target=work, daemon=True).start()

    def _finished(self, _action, result):
        for button in self.buttons:
            button.setDisabled(False)
        self.refresh()
        self.status.setText(f"Couldn't do that: {result}" if isinstance(result, Exception) else result)

    def _add(self, source):
        name, ok = QInputDialog.getText(self, "Add a blocklist", "Name for this list:",
                                        text=suggest_list_name(source))
        if ok and name.strip():
            name = name.strip()
            self._run(f"Getting {name}…", lambda: f"Added {name} "
                      f"({dns_proxy.add_custom_list(name, source):,} domains).")

    def add_url(self):
        url, ok = QInputDialog.getText(self, "Add a blocklist", "URL of the list:")
        url = url.strip()
        if ok and url:
            self._add(url if "://" in url else "https://" + url)

    def add_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose a blocklist", os.path.expanduser("~"),
                                              "Lists (*.txt *.hosts *.list);;All files (*)")
        if path:
            self._add(path)

    def update_selected(self):
        name = self._selected()
        if name:
            self._run(f"Updating {name}…", lambda: f"Updated {name} "
                      f"({dns_proxy.update_custom_list(name):,} domains).")

    def remove_selected(self):
        name = self._selected()
        if name and QMessageBox.question(self, "Privacy Shield",
                                         f"Remove the {name} list?") == QMessageBox.Yes:
            dns_proxy.remove_custom_list(name)
            self.refresh()
            self.status.setText(f"Removed {name}.")


class PrivacyShieldApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Privacy Shield" + (" (dry run)" if DRY_RUN else ""))
        self.resize(360, 620)

        self.bridge = Bridge()
        self.bridge.done.connect(self.on_done)
        self.bridge.helper_event.connect(self.on_helper_event)
        self.bridge.mullvad.connect(self.on_mullvad_status)
        self.helper = HelperConnection(self.bridge.helper_event.emit)
        self.server = None
        self.active = False
        self.closing = False
        self.mullvad_state = None
        self.analytics = None
        self._shown_recent = []

        layout = QVBoxLayout()

        self.status_label = QLabel("Off")
        self.status_label.setStyleSheet("font-weight: bold; font-size: 15px;")
        layout.addWidget(self.status_label)
        self.detail_label = QLabel("")
        self.detail_label.setWordWrap(True)
        layout.addWidget(self.detail_label)

        stats_row = QHBoxLayout()
        self.label = QLabel("Trackers blocked: 0 this session")
        stats_row.addWidget(self.label, 1)
        analytics_btn = QPushButton("Analytics…")
        analytics_btn.clicked.connect(self.open_analytics)
        stats_row.addWidget(analytics_btn)
        layout.addLayout(stats_row)

        # Dropdown with multiple checkable blocklists: the bundled ones plus any you added
        self.combo = CheckableComboBox()
        self.settings = QSettings("PrivacyShield", "PrivacyShield")
        self.populate_lists(self.settings.value("blocklists", [], type=list))  # last time's picks

        self.combo.setStyleSheet("""
            QComboBox {
                border: 1px solid gray;
                border-radius: 6px;
                padding: 4px 30px 4px 8px;   /* room for arrow */
                background-color: #2b2b2b;   /* dark mode friendly */
                color: white;                /* text color */
            }
            QComboBox:focus {
                border: 1px solid #888;
                outline: none;
            }
            QComboBox::drop-down {
                subcontrol-origin: padding;
                subcontrol-position: top right;
                width: 20px;
                border: none;
            }
            QComboBox::down-arrow {
                image: url(/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/Actions.icns);
                width: 12px;
                height: 12px;
            }
        """)

        lists_row = QHBoxLayout()
        lists_row.addWidget(self.combo, 1)
        custom_btn = QPushButton("Custom lists…")
        custom_btn.clicked.connect(self.manage_lists)
        lists_row.addWidget(custom_btn)
        layout.addLayout(lists_row)

        self.active_label = QLabel("Active blocklists: none")
        layout.addWidget(self.active_label)

        self.start_btn = QPushButton("Start DNS Proxy")
        self.start_btn.clicked.connect(self.start_proxy)
        layout.addWidget(self.start_btn)

        self.stop_btn = QPushButton("Stop DNS Proxy")
        self.stop_btn.clicked.connect(self.stop_proxy)
        self.stop_btn.setDisabled(True)
        layout.addWidget(self.stop_btn)

        layout.addWidget(QLabel("Recently blocked (double-click one to allow it):"))
        self.recent_list = QListWidget()
        self.recent_list.itemDoubleClicked.connect(self.allow_domain)
        layout.addWidget(self.recent_list)

        layout.addWidget(QLabel("Always block or allow a domain (subdomains included):"))
        rule_row = QHBoxLayout()
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("example.com")
        rule_row.addWidget(self.domain_input, 1)
        for text, block in (("Block", True), ("Allow", False)):
            button = QPushButton(text)
            button.clicked.connect(lambda _, block=block: self.add_rule(block))
            rule_row.addWidget(button)
        layout.addLayout(rule_row)
        edit_row = QHBoxLayout()
        for text, path in (("Edit blacklist…", dns_proxy.BLACKLIST_FILE),
                           ("Edit whitelist…", dns_proxy.WHITELIST_FILE)):
            button = QPushButton(text)
            button.clicked.connect(lambda _, path=path: open_in_editor(path))
            edit_row.addWidget(button)
        layout.addLayout(edit_row)
        self.rule_label = QLabel("")
        self.rule_label.setWordWrap(True)
        layout.addWidget(self.rule_label)

        self.footer_label = QLabel("")
        self.footer_label.setWordWrap(True)
        self.footer_label.setStyleSheet("color: gray;")
        layout.addWidget(self.footer_label)

        self.setLayout(layout)

        self.timer = QTimer()
        self.timer.timeout.connect(self.update_stats)
        self.timer.start(1000)

        self.mullvad_timer = QTimer()
        self.mullvad_timer.timeout.connect(self.poll_mullvad)
        self.mullvad_timer.start(5000)
        self.poll_mullvad()

        if not DRY_RUN and os.path.exists(STATE_FILE) and not helper_running():
            QTimer.singleShot(300, self.offer_restore)

        threading.Thread(target=self._refresh_lists, daemon=True).start()

    # ----- start / stop (the slow parts run on a worker thread) -----
    def _in_background(self, action, fn, *args):
        def work():
            try:
                result = fn(*args)
            except Exception as e:
                if not isinstance(e, HelperError):
                    traceback.print_exc()
                result = e
            self.bridge.done.emit(action, result)

        threading.Thread(target=work, daemon=True).start()

    def set_status(self, text, detail=""):
        self.status_label.setText(text)
        self.detail_label.setText(detail)

    def start_proxy(self):
        names = self.combo.checked_items()
        if not names:
            self.active_label.setText("Active blocklists: none (select at least one)")
            return
        self.settings.setValue("blocklists", names)
        self.start_btn.setDisabled(True)
        self.combo.setDisabled(True)
        self.set_status("Starting…", "" if self.helper.connected else
                        "macOS will ask for your password so Privacy Shield can change DNS settings.")
        self._in_background("start", self._start, names)

    def _start(self, names):
        if not self.helper.connected:
            self.helper.launch()
        udp, tcp = self.helper.sockets
        lists = {name: path for name in names if (path := dns_proxy.blocklist_path(name))}
        server = dns_proxy.ShieldServer(udp, tcp, lists)
        server.start()
        # Only touch DNS settings once the shield has proven it can answer.
        if not dns_proxy.probe(self.helper.port):
            server.stop()
            raise HelperError("Couldn't look anything up through the shield (no DNS-over-HTTPS "
                              "server or network DNS answered), so your DNS settings were left alone.")
        try:
            reply = self.helper.request("apply")
            if not reply.get("ok"):
                raise HelperError("Couldn't change DNS settings: "
                                  + "; ".join(reply.get("errors") or ["unknown error"]))
        except HelperError:
            try:
                self.helper.request("restore")
            except HelperError:
                pass
            server.stop()
            raise
        return names, server, reply

    def stop_proxy(self):
        self.stop_btn.setDisabled(True)
        self.set_status("Stopping…")
        self._in_background("stop", self._stop)

    def _stop(self):
        server, self.server = self.server, None
        try:
            if not self.helper.connected:
                # The old helper died. Stop serving so a new helper can take port 53, then
                # have it restore from the saved state.
                if server:
                    server.stop()
                    server = None
                self.helper.launch()
            reply = self.helper.request("restore")  # while the shield is still answering
            if not reply.get("ok"):
                raise HelperError("; ".join(reply.get("errors") or ["unknown error"]))
        finally:
            if server:
                server.stop()

    def offer_restore(self):
        answer = QMessageBox.question(
            self, "Privacy Shield",
            "Privacy Shield didn't get to put your DNS settings back last time (it was force-quit, "
            "or the Mac lost power). If websites aren't loading, this is why.\n\n"
            "Restore your DNS settings now? macOS will ask for your password.")
        if answer == QMessageBox.Yes:
            self.start_btn.setDisabled(True)
            self.set_status("Restoring…")
            self._in_background("restore", self._restore_leftovers)

    def _restore_leftovers(self):
        if not self.helper.connected:
            self.helper.launch()
        reply = self.helper.request("restore")  # nothing applied yet, so it uses state.json
        if not reply.get("ok"):
            raise HelperError("; ".join(reply.get("errors") or ["unknown error"]))

    def on_done(self, action, result):
        failed = isinstance(result, Exception)
        if action == "start" and failed:
            self.set_status("Off", f"Couldn't start: {result}")
            self.start_btn.setDisabled(False)
            self.combo.setDisabled(False)
        elif action == "start":
            names, self.server, reply = result
            self.active = True
            self.stop_btn.setDisabled(False)
            self.active_label.setText("Active blocklists: " + ", ".join(names))
            detail = f"DNS goes through Privacy Shield on: {', '.join(reply['services'])}."
            if reply.get("mullvad") != "not installed":
                detail += f"\nMullvad: {reply['mullvad']} (used while the VPN is connected)."
            if reply.get("errors"):
                detail += "\nWarnings: " + "; ".join(reply["errors"])
            if DRY_RUN:
                detail = f"Dry run: no settings were changed (see {HELPER_LOG}).\n" + detail
            self.set_status("Protected", detail)
        else:  # stop / restore
            self.active = False
            self.start_btn.setDisabled(False)
            self.stop_btn.setDisabled(True)
            self.combo.setDisabled(False)
            self.active_label.setText("Active blocklists: none")
            if failed:
                self.set_status("Off", f"DNS settings may not be fully restored: {result}\n"
                                       f"Fix in Terminal: {restore_command()}")
            else:
                self.set_status("Off", "Your normal DNS settings are back.")

    def on_helper_event(self, msg):
        event = msg.get("event")
        if event == "restored" and self.active:
            # The helper's watchdog put DNS back because the shield stopped answering.
            self.on_done("stop", None)
            server, self.server = self.server, None
            if server:
                server.stop()
            self.set_status("Off", msg.get("reason", ""))
        elif event == "gone" and self.active and not self.closing:
            self.detail_label.setText(
                "The helper that manages DNS settings exited unexpectedly. The shield is still "
                "answering; click Stop to put your DNS back (macOS will ask for your password).")

    # ----- your lists (a running shield reloads them within a second or two) -----
    def populate_lists(self, checked):
        available = dns_proxy.available_blocklists()
        names = ([n for n in LIST_ORDER if n in available]
                 + sorted((n for n in available if n not in LIST_ORDER), key=str.lower))
        self.combo.set_items(names, set(checked))

    def manage_lists(self):
        before = set(dns_proxy.available_blocklists())
        ListsDialog(self).exec_()
        added = set(dns_proxy.available_blocklists()) - before
        self.populate_lists(set(self.combo.checked_items()) | added)  # new lists start ticked

    @staticmethod
    def _refresh_lists():
        for name, result in dns_proxy.refresh_custom_lists().items():
            print(f"[+] Refreshed list {name}: {result}")

    def add_rule(self, block):
        text = self.domain_input.text().strip()
        name = domain_from_input(text)
        if not name:
            self.rule_label.setText(f"“{text}” isn't a domain name." if text else "Type a domain first.")
            return
        set_rule(name, block)
        self.domain_input.clear()
        self.rule_label.setText(f"{name} is now always {'blocked' if block else 'allowed'}.")

    def allow_domain(self, item):
        name = item.text()
        answer = QMessageBox.question(
            self, "Privacy Shield",
            f"Stop blocking {name}?\n\nIt's added to your whitelist (subdomains included) and "
            "takes effect within a few seconds. Reload the page afterwards.")
        if answer == QMessageBox.Yes:
            set_rule(name, block=False)
            self.rule_label.setText(f"{name} is now always allowed.")

    # ----- status display -----
    def update_stats(self):
        s = dns_proxy.stats
        self.label.setText(f"Trackers blocked: {s.session_blocked:,} this session, "
                           f"{s.total_blocked:,} all time")
        recent = s.recent_blocked(50)
        if recent != self._shown_recent:
            self._shown_recent = recent
            self.recent_list.clear()
            self.recent_list.addItems(recent)
        self._update_footer()

    def open_analytics(self):
        if self.analytics is None:
            self.analytics = analytics.AnalyticsDialog(self)
        self.analytics.show()
        self.analytics.raise_()
        self.analytics.activateWindow()

    def poll_mullvad(self):
        threading.Thread(target=lambda: self.bridge.mullvad.emit(mullvad_status()), daemon=True).start()

    def on_mullvad_status(self, status):
        self.mullvad_state = status
        self._update_footer()

    def _update_footer(self):
        lines = []
        server = self.server
        if server and server.upstreams.last_used:
            lines.append(f"Upstream: {server.upstreams.last_used}")
        s = dns_proxy.stats
        if server and s.session_allowed:
            lines.append(f"Answered from cache: {100 * s.cache_hits // s.session_allowed}% of lookups")
        if server and s.failed:
            lines.append(f"Lookups that got no answer: {s.failed}")
        if self.mullvad_state:
            lines.append(f"Mullvad: {self.mullvad_state}")
        self.footer_label.setText("\n".join(lines))

    # ----- quitting -----
    def closeEvent(self, event):
        self.shutdown()
        super().closeEvent(event)

    def shutdown(self):
        """Put DNS back before we exit. (If we die without getting here, the helper notices
        the connection drop and restores DNS itself.)"""
        if self.closing:
            return
        self.closing = True
        if self.active and self.helper.connected:
            try:
                self.helper.request("restore", timeout=20)
            except HelperError as e:
                print(f"[!] {e}")
        elif self.active:
            print("[!] The DNS helper is gone, so DNS may still point at Privacy Shield. "
                  f"Fix: {restore_command()}")
        self.helper.close()
        server, self.server = self.server, None
        if server:
            server.stop()
        dns_proxy.stats.flush()


def selftest():
    """--selftest: check this copy works end to end without changing any settings. Runs the
    helper handoff in dry-run mode on port 5300, a DNS-over-HTTPS lookup, and blocking."""
    global DRY_RUN
    DRY_RUN = True
    dns_proxy.stats = dns_proxy.Stats(os.path.join(tempfile.mkdtemp(), "stats.db"))
    lists = dns_proxy.available_blocklists()
    print("Blocklists:", ", ".join(lists))
    helper, server, checks = HelperConnection(lambda msg: None), None, []
    try:
        helper.launch(timeout=30)
        checks.append(("helper started and handed over its sockets", True))
        server = dns_proxy.ShieldServer(*helper.sockets, lists)
        server.start()
        checks.append(("example.com resolves through the shield", dns_proxy.probe(helper.port)))
        checks.append(("doubleclick.net is blocked",
                       dns_proxy.lookup("doubleclick.net", helper.port) == ["0.0.0.0"]))
        hits = dns_proxy.stats.cache_hits
        dns_proxy.lookup("example.com", helper.port)
        checks.append(("a repeat lookup is answered from the cache", dns_proxy.stats.cache_hits == hits + 1))
        checks.append(("helper apply/restore (dry run)",
                       helper.request("apply").get("ok") and helper.request("restore").get("ok")))
        print("Upstream:", server.upstreams.last_used)
    except Exception as e:
        checks.append((f"error: {e}", False))
    finally:
        if server:
            server.stop()
        helper.close()
    for name, ok in checks:
        print("ok  " if ok else "FAIL", name)
    return 0 if all(ok for _, ok in checks) else 1


def main():
    if "--selftest" in sys.argv:
        sys.exit(selftest())
    # One copy at a time: two would fight over port 53 and over your DNS settings.
    os.makedirs(dns_proxy.SUPPORT_DIR, exist_ok=True)
    lock = open(os.path.join(dns_proxy.SUPPORT_DIR, "app.lock"), "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        app = QApplication(sys.argv)  # keep a reference: the message box needs it alive  # noqa: F841
        QMessageBox.information(None, "Privacy Shield", "Privacy Shield is already open.")
        sys.exit(0)
    if dns_proxy.FROZEN:
        # A double-clicked app has no terminal; keep its output where ps_diag.sh can find it.
        os.makedirs(os.path.dirname(APP_LOG), exist_ok=True)
        if os.path.exists(APP_LOG) and os.path.getsize(APP_LOG) > 1_000_000:
            os.replace(APP_LOG, APP_LOG + ".old")
        sys.stdout = sys.stderr = open(APP_LOG, "a", buffering=1)

    # Reset session counters on app launch (once)
    try:
        dns_proxy.start_new_session()
    except Exception as e:
        print(f"[!] Couldn't reset stats session on launch: {e}")

    app = QApplication(sys.argv)
    window = PrivacyShieldApp()
    app.aboutToQuit.connect(window.shutdown)
    # Ctrl-C, closing the terminal, or `kill` quit cleanly so DNS gets restored. The timer gives
    # Python a chance to run signal handlers while Qt's event loop is in control.
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, lambda *_: app.quit())
    tick = QTimer()
    tick.timeout.connect(lambda: None)
    tick.start(250)
    sys.excepthook = traceback.print_exception  # a bug in one handler shouldn't kill the app
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
