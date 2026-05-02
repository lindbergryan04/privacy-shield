import sys, json, threading, subprocess, os, tempfile, requests
from PyQt5.QtWidgets import (
    QApplication,
    QWidget,
    QLabel,
    QVBoxLayout,
    QPushButton,
    QComboBox,
    QStyledItemDelegate,
)
from PyQt5.QtCore import Qt, QTimer
import dns_proxy
from dns_proxy import STATS_FILE


class CheckableComboBox(QComboBox):
    """
    QComboBox with checkable items for multi-select.
    """

    def __init__(self):
        super().__init__()
        self.view().pressed.connect(self.handle_item_pressed)
        self.setItemDelegate(QStyledItemDelegate())
        self.setEditable(True)
        self.lineEdit().setReadOnly(True)
        self.lineEdit().setPlaceholderText("Select blocklists...")

    def handle_item_pressed(self, index):
        item = self.model().itemFromIndex(index)
        if item.checkState() == Qt.Checked:
            item.setCheckState(Qt.Unchecked)
        else:
            item.setCheckState(Qt.Checked)
        self.update_text()

    def update_text(self):
        selected = [self.itemText(i) for i in range(self.count())
                    if self.model().item(i).checkState() == Qt.Checked]
        self.lineEdit().setText(", ".join(selected) if selected else "None")

    def checked_items(self):
        return [self.itemText(i) for i in range(self.count())
                if self.model().item(i).checkState() == Qt.Checked]


class PrivacyShieldApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Privacy Shield")
        self.resize(300, 250)

        layout = QVBoxLayout()

        self.label = QLabel("Trackers blocked this session: 0")
        layout.addWidget(self.label)

        # Dropdown with multiple checkable blocklists
        self.combo = CheckableComboBox()
        for name in ["Strict", "Moderate", "Permissive", "Streaming", "Social", "Adult"]:
            self.combo.addItem(name)
            item = self.combo.model().item(self.combo.count() - 1)
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            item.setCheckState(Qt.Unchecked)

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

        layout.addWidget(self.combo)

        self.active_label = QLabel("Active blocklists: none")
        layout.addWidget(self.active_label)

        self.start_btn = QPushButton("Start DNS Proxy")
        self.start_btn.clicked.connect(self.start_proxy)
        layout.addWidget(self.start_btn)

        self.stop_btn = QPushButton("Stop DNS Proxy")
        self.stop_btn.clicked.connect(self.stop_proxy)
        self.stop_btn.setDisabled(True)
        layout.addWidget(self.stop_btn)

        self.setLayout(layout)

        self.timer = QTimer()
        self.timer.timeout.connect(self.update_stats)
        self.timer.start(1000)

        # proxy state
        self.stop_event = None
        self.thread = None

    def get_selected_blocklists(self):
        return [f"blocklists/{name.lower()}.txt" for name in self.combo.checked_items()]

    def _service_name_for_en0(self):
        """
        Resolve the network service name associated with en0.
        Example: 'Wi-Fi'.
        """
        try:
            out = subprocess.check_output(
                ["networksetup", "-listallhardwareports"], text=True
            )
            blocks = out.strip().split("\n\n")
            for block in blocks:
                lines = dict(line.split(": ", 1) for line in block.splitlines() if ": " in line)
                if lines.get("Device") == "en0":
                    return lines.get("Hardware Port")
        except Exception as e:
            print(f"[!] Failed to resolve service for en0: {e}")
        return "Wi-Fi"  # fallback

    # Cloudflare DoH IPs (avoids needing DNS bootstrap)
    CLOUDFLARE_DOH_IPS = ["104.16.248.249", "104.16.249.249"]
    CLOUDFLARE_DOH_HOST = "cloudflare-dns.com"
    CLOUDFLARE_DOH_PATH = "/dns-query"

    def doh_query(self, dns_query_bytes):
        headers = {
            "Content-Type": "application/dns-message",
            "Accept": "application/dns-message",
            "Host": self.CLOUDFLARE_DOH_HOST,  # TLS SNI + Host header
        }

        # try both IPs for resilience
        for ip in self.CLOUDFLARE_DOH_IPS:
            url = f"https://{ip}{self.CLOUDFLARE_DOH_PATH}"
            try:
                resp = requests.post(url, headers=headers, data=dns_query_bytes, timeout=5, verify=True)
                if resp.status_code == 200:
                    return resp.content
            except Exception as e:
                print(f"[!] DoH lookup failed via {ip}: {e}")
        
        return None

    def start_proxy(self):
        blocklists = self.get_selected_blocklists()
        if not blocklists:
            self.active_label.setText("Active blocklists: none (select at least one)")
            return

        self.active_label.setText("Active blocklists: " + ", ".join(self.combo.checked_items()))

        # Start proxy thread
        self.stop_event = threading.Event()
        self.thread = threading.Thread(
            target=dns_proxy.run_dns,
            args=(blocklists, self.stop_event, 5300),
            daemon=True,
        )
        self.thread.start()

        # Get network service for en0
        self.network_service = self._service_name_for_en0()

        # Save existing DNS servers
        try:
            prev = subprocess.check_output(
                ["networksetup", "-getdnsservers", self.network_service], text=True
            ).strip().splitlines()
            if prev and "There aren't any DNS Servers set" in prev[0]:
                self.prev_dns_servers = []
            else:
                self.prev_dns_servers = [s.strip() for s in prev if s.strip()]
        except subprocess.CalledProcessError:
            self.prev_dns_servers = []

        # Always reset first, then set to 127.0.0.1 (avoids lengthening chain)
        try:
            subprocess.run(
                ["sudo", "networksetup", "-setdnsservers", self.network_service, "Empty"],
                check=True,
            )
            subprocess.run(
                ["sudo", "networksetup", "-setdnsservers", self.network_service, "127.0.0.1"],
                check=True,
            )
            print(f"[+] DNS for '{self.network_service}' set to 127.0.0.1")
        except subprocess.CalledProcessError as e:
            print(f"[!] Failed to set DNS servers: {e}")

        # rdr rules on lo0
        DOH_IPS = [
            "1.1.1.1", "1.0.0.1",
            "8.8.8.8", "8.8.4.4",
            "9.9.9.9", "149.112.112.112",
            "94.140.14.14", "94.140.15.15"
        ]

        # Explicit pass-out for DoH IPs on port 443 (avoid proxy self-blocking)
        pass_out = "pass out on en0 proto tcp from any to { " + " ".join(DOH_IPS) + " } port 443 keep state"

        rdr_rules = f"""\
        # Redirect all DNS (UDP/TCP 53) on lo0 into our proxy
        rdr pass on lo0 inet proto udp from any to 127.0.0.1 port 53 -> 127.0.0.1 port 5300
        rdr pass on lo0 inet proto tcp from any to 127.0.0.1 port 53 -> 127.0.0.1 port 5300

        # Allow outbound HTTPS to DoH providers (Cloudflare, Google, Quad9, AdGuard)
        {pass_out}
        """


        try:
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                tmp.write(rdr_rules.encode())
                tmp_path = tmp.name

            self.anchor_name = "com.apple/PrivacyShield"
            subprocess.run(["sudo", "pfctl", "-a", self.anchor_name, "-f", tmp_path], check=True)

            status = subprocess.run(["sudo", "pfctl", "-s", "info"], capture_output=True, text=True)
            if "Status: Disabled" in status.stdout:
                subprocess.run(["sudo", "pfctl", "-e"], check=True)

            print(f"[+] PrivacyShield rdr rules loaded into anchor {self.anchor_name}")
        except subprocess.CalledProcessError as e:
            print(f"[!] Failed to enable pfctl redirect: {e}")

        self.start_btn.setDisabled(True)
        self.stop_btn.setDisabled(False)


    def stop_proxy(self):
        if self.stop_event:
            self.stop_event.set()
            self.thread.join(timeout=1)
            self.thread = None

        # Flush our PF anchor rules
        try:
            if hasattr(self, "anchor_name"):
                subprocess.run(["sudo", "pfctl", "-a", self.anchor_name, "-F", "all"], check=True)
                print(f"[+] Flushed PrivacyShield rules from {self.anchor_name}")
        except subprocess.CalledProcessError as e:
            print(f"[!] Failed to flush PrivacyShield rules: {e}")

        # Restore DNS servers
        try:
            if getattr(self, "prev_dns_servers", None):
                subprocess.run(
                    ["sudo", "networksetup", "-setdnsservers", self.network_service, *self.prev_dns_servers],
                    check=True,
                )
                print(f"[+] Restored DNS for '{self.network_service}' to: {', '.join(self.prev_dns_servers)}")
            else:
                subprocess.run(
                    ["sudo", "networksetup", "-setdnsservers", self.network_service, "Empty"],
                    check=True,
                )
                print(f"[+] Cleared custom DNS for '{self.network_service}' (back to DHCP)")

                # Show which resolver is now being used
                result = subprocess.run(
                    ["networksetup", "-getdnsservers", self.network_service],
                    capture_output=True, text=True
                )
                dns_info = result.stdout.strip()
                if "There aren't any DNS Servers set" in dns_info:
                    print(f"[i] '{self.network_service}' is now using DHCP/default resolvers.")
                else:
                    print(f"[i] '{self.network_service}' current DNS resolvers: {dns_info}")
        except subprocess.CalledProcessError as e:
            print(f"[!] Failed to restore DNS servers: {e}")

        # Keep pf enabled for system use
        status = subprocess.run(["sudo", "pfctl", "-s", "info"], capture_output=True, text=True)
        if "Status: Disabled" in status.stdout:
            subprocess.run(["sudo", "pfctl", "-e"], check=False)

        self.start_btn.setDisabled(False)
        self.stop_btn.setDisabled(True)
        self.active_label.setText("Active blocklists: none")

    def update_stats(self):
        try:
            with open(STATS_FILE, "r") as f:
                stats = json.load(f)
            # Prefer session counter; fall back to cumulative if session key missing
            count = stats.get("session_blocked", stats.get("blocked", 0))
            self.label.setText(f"Trackers blocked this session: {count}")
        except (FileNotFoundError, json.JSONDecodeError):
            self.label.setText("Trackers blocked this session: 0")


if __name__ == "__main__":
     # Reset session counters on app launch (once)
    try:
        dns_proxy.start_new_session()
    except Exception as e:
        print(f"[!] Couldn't reset stats session on launch: {e}")

    app = QApplication(sys.argv)
    window = PrivacyShieldApp()
    window.show()
    sys.exit(app.exec_())
