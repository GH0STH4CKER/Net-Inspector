import sys
import os
import re
import time
import subprocess
import platform
import threading
import shutil
from datetime import datetime
from collections import defaultdict
from functools import partial
from PyQt5.QtCore import QTimer

# If you set a Qt plugin path, keep it, otherwise remove this line.
os.environ['QT_QPA_PLATFORM_PLUGIN_PATH'] = r"C:\Users\ASUS~1\AppData\Local\Programs\Python\Python310\Lib\site-packages\PyQt5\Qt5\plugins\platforms"

import matplotlib as mpl
mpl.rcParams["legend.labelcolor"] = "#ffffff"
mpl.rcParams["legend.facecolor"] = "none"

# PyQt5
from PyQt5.QtCore import Qt, pyqtSignal, QThread
from PyQt5.QtGui import QIcon, QPalette, QColor
from PyQt5.QtWidgets import (
    QApplication, QWidget, QTabWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QTableWidget, QTableWidgetItem, QLabel, QHeaderView, QProgressBar,
    QMessageBox, QComboBox, QSplitter
)

# Matplotlib backend for Qt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

# Networking libs (optional)
try:
    from scapy.all import ARP, Ether, srp, conf
except Exception:
    ARP = Ether = srp = conf = None

try:
    import netifaces
except Exception:
    netifaces = None

try:
    import pywifi
    from pywifi import const as wifi_const
except Exception:
    pywifi = None
    wifi_const = None

try:
    import sys
    from mac_vendor_lookup import MacLookup

    # When running as EXE, __file__ is inside a temp folder
    if getattr(sys, 'frozen', False):
        # PyInstaller puts extra files in sys._MEIPASS
        base_path = sys._MEIPASS
        oui_path = os.path.join(base_path, "mac_vendor_lookup", "oui.txt")

        # Force MacLookup to use the bundled file
        mac_lookup = MacLookup()
        if os.path.exists(oui_path):
            mac_lookup.load_vendors(oui_path)
        else:
            mac_lookup = MacLookup()  # fallback (may be empty)
    else:
        # Normal Python mode
        mac_lookup = MacLookup()
except Exception:
    mac_lookup = None

# Requests for internet API lookups
try:
    import requests
except Exception:
    requests = None

APP_NAME = "NetInspector by GH0STH4CKER"

# ---------------------------
# Helper: run external commands without showing a console on Windows
# ---------------------------
def run_cmd(cmd, timeout=4, shell=False):
    """
    Run a command and return decoded stdout string (or empty string on error).
    cmd: list (preferred) or string.
    shell: set True if you pass a command string that needs shell parsing.
    """
    try:
        # Prepare creationflags/startupinfo for Windows to avoid child console flash
        creationflags = 0
        startupinfo = None
        if platform.system() == "Windows":
            creationflags = subprocess.CREATE_NO_WINDOW
            # also set STARTF_USESHOWWINDOW to be extra safe
            try:
                si = subprocess.STARTUPINFO()
                si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startupinfo = si
            except Exception:
                startupinfo = None

        # If cmd is a list -> shell=False recommended
        if isinstance(cmd, (list, tuple)):
            data = subprocess.check_output(cmd, timeout=timeout, stderr=subprocess.STDOUT,
                                           startupinfo=startupinfo, creationflags=creationflags)
        else:
            # cmd is string
            data = subprocess.check_output(cmd, timeout=timeout, stderr=subprocess.STDOUT,
                                           startupinfo=startupinfo, creationflags=creationflags, shell=True)
        return data.decode(errors="ignore")
    except subprocess.CalledProcessError as e:
        # Return stdout/stderr combined if present
        try:
            return (e.output or b"").decode(errors="ignore")
        except Exception:
            return ""
    except Exception:
        return ""

# ---------------------------
# UI THEME AND VISUAL STYLING
# ---------------------------
def apply_dark_theme(app: QApplication):
    app.setStyle("Fusion")
    palette = QPalette()

    # Dark colors
    palette.setColor(QPalette.Window, QColor(28, 28, 30))
    palette.setColor(QPalette.WindowText, Qt.white)
    palette.setColor(QPalette.Base, QColor(18, 18, 20))
    palette.setColor(QPalette.AlternateBase, QColor(24, 24, 26))
    palette.setColor(QPalette.Text, Qt.white)
    palette.setColor(QPalette.Button, QColor(40, 40, 44))
    palette.setColor(QPalette.ButtonText, Qt.white)
    palette.setColor(QPalette.Highlight, QColor(76, 120, 168))
    palette.setColor(QPalette.HighlightedText, Qt.white)

    app.setPalette(palette)

    app.setStyleSheet("""
        QWidget { font-size: 18px; color: #EEE; }
        QTabBar::tab { background: #2b2b2f; color: #ddd; padding: 8px 16px; font-size: 18px; }
        QTabBar::tab:selected { background: #3a3a40; color: #fff; }
        QTableWidget { background: #1b1b1d; gridline-color: #3a3a3a; font-size: 17px; }
        QHeaderView::section { background-color: #34343a; color: #e6e6e6; padding: 6px; font-size: 17px; }
        QPushButton { background-color: #4C78A8; color: white; border-radius: 8px; padding: 8px 14px; font-size: 18px; }
        QPushButton:hover { background-color: #5a89bf; }
        QProgressBar { border: 1px solid #444; border-radius: 5px; text-align: center; font-size: 16px; }
        QProgressBar::chunk { background-color: #4C78A8; }
    """)

# ---------------------------
# SYSTEM / NETWORK HELPERS
# ---------------------------
def is_admin():
    system = platform.system()
    if system == "Windows":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    else:
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False

def oui_vendor(mac):
    """
    Use online API (api.macvendors.com) to fetch vendor string.
    Returns vendor string, or 'Internet required' if lookup cannot be done,
    or 'Not Found' on lookup failure.
    """
    if not mac:
        return ""
    mac = mac.strip().upper()
    # Prefer online lookup via api.macvendors.com
    try:
        if requests is None:
            return "Internet required"
        url = f"https://api.macvendors.com/{mac}"
        try:
            resp = requests.get(url, timeout=3)
            if resp.status_code == 200:
                txt = resp.text.strip()
                return txt if txt else "Not Found"
            else:
                # Non-200: return hint if probably offline or blocked
                return "Not Found"
        except requests.RequestException:
            return "Internet required"
    except Exception:
        return "Not Found"

def local_ipv4_candidates():
    cands = set()
    if netifaces:
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])
            for a in addrs:
                ip = a.get('addr', '')
                if ip.startswith("192.168."):
                    parts = ip.split(".")
                    if len(parts) == 4:
                        cands.add(f"{parts[0]}.{parts[1]}.0.0/16")
    if not cands:
        cands.add("192.168.0.0/16")
    return list(cands)

def scapy_arp_scan(cidr, timeout=0.8, retry=1):
    results = []
    if ARP is None:
        return results
    try:
        conf.verb = 0
    except Exception:
        pass
    try:
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr)
        ans, _ = srp(pkt, timeout=timeout, retry=retry)
        for _, rcv in ans:
            results.append({"ip": rcv.psrc, "mac": rcv.hwsrc})
    except Exception:
        pass
    return results

def freq_band(freq_mhz):
    try:
        f = float(freq_mhz)
        if 2400 <= f < 2500:
            return "2.4 GHz"
        if 5000 <= f < 6000:
            return "5 GHz"
        if 5925 <= f < 7125:
            return "6 GHz"
    except Exception:
        pass
    return ""

def channel_from_freq(freq_mhz, ssid=""):
    try:
        f = float(freq_mhz)
        if 2400 <= f < 2500:
            return int(round((f - 2412) / 5) + 1)
        if 5000 <= f < 6000:
            base = 5000
            return int((f - base) / 5)
        if 5925 <= f < 7125:
            return int((f - 5955) / 5)
    except Exception:
        pass
    return 0

def parse_security(info):
    text = (info or "").upper()
    if "WPA3" in text:
        return "WPA3"
    if "WPA2" in text:
        return "WPA2"
    if "WPA" in text and "WPA2" not in text:
        return "WPA"
    if "WEP" in text:
        return "WEP"
    if "OPEN" in text or "NONE" in text:
        return "Open"
    return "Unknown"

# ---------------------------
# THREADS
# ---------------------------
class LANScannerThread(QThread):
    progress = pyqtSignal(int)
    found = pyqtSignal(dict)
    done = pyqtSignal()

    def __init__(self, cidrs, parent=None):
        super().__init__(parent)
        self.cidrs = cidrs
        self._stop = threading.Event()

    def run(self):
        total = len(self.cidrs)
        for i, cidr in enumerate(self.cidrs, start=1):
            if self._stop.is_set():
                break
            hosts = scapy_arp_scan(cidr)
            for h in hosts:
                h["vendor"] = oui_vendor(h.get("mac"))
                h["model"] = ""
                self.found.emit(h)
            self.progress.emit(int(i * 100 / total))
        self.done.emit()

    def stop(self):
        self._stop.set()

class WifiScannerThread(QThread):
    updated = pyqtSignal(list)

    def __init__(self, interval_ms=1500, parent=None):
        super().__init__(parent)
        self._stop = threading.Event()
        self.interval = interval_ms / 1000.0

    def run(self):
        while not self._stop.is_set():
            nets = self.scan_once()
            self.updated.emit(nets)
            time.sleep(self.interval)

    def stop(self):
        self._stop.set()

    def scan_once(self):
        system = platform.system()
        nets = []

        # Preferred: pywifi
        try:
            if pywifi:
                try:
                    wifi = pywifi.PyWiFi()
                    iface = wifi.interfaces()[0] if wifi.interfaces() else None
                except Exception:
                    iface = None
                if iface:
                    try:
                        iface.scan()
                        time.sleep(0.8)
                        results = iface.scan_results()
                        for r in results:
                            ssid = getattr(r, "ssid", "") or "<hidden>"
                            rssi = getattr(r, "signal", -100)
                            freq = getattr(r, "freq", 0)
                            akm = getattr(r, "akm", []) or []
                            bssid = getattr(r, "bssid", "") or getattr(r, "bssid", "") or ""
                            sec = "Unknown"
                            if akm and wifi_const:
                                try:
                                    if wifi_const.AKM_TYPE_WPA3 in akm:
                                        sec = "WPA3"
                                    elif wifi_const.AKM_TYPE_WPA2 in akm:
                                        sec = "WPA2"
                                    elif wifi_const.AKM_TYPE_WPA in akm:
                                        sec = "WPA"
                                    elif wifi_const.AKM_TYPE_NONE in akm:
                                        sec = "Open"
                                except Exception:
                                    pass
                            band = freq_band(freq) if freq else ""
                            ch = channel_from_freq(freq, ssid) if freq else 0
                            nets.append({"ssid": ssid, "rssi": rssi, "freq": freq, "band": band, "channel": ch, "security": sec, "bssid": bssid})
                        if nets:
                            return nets
                    except Exception:
                        pass
        except Exception:
            pass

        # macOS fallback
        if system == "Darwin":
            try:
                airport = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
                out = run_cmd([airport, "-s"], timeout=4)
                lines = out.strip().splitlines()
                for ln in lines[1:] if len(lines) > 1 and "SSID" in lines[0] else lines:
                    parts = re.split(r'\s{2,}', ln.strip())
                    if len(parts) >= 5:
                        ssid = parts[0] or "<hidden>"
                        rssi = int(parts[2]) if parts[2].lstrip("-").isdigit() else -100
                        ch = int(re.sub(r'[^0-9]', '', parts[3]) or 0)
                        band = "2.4 GHz" if ch and ch <= 14 else ("5 GHz" if ch and ch < 200 else ("6 GHz" if ch and ch >= 200 else ""))
                        sec = parse_security(parts[-1])
                        nets.append({"ssid": ssid, "rssi": rssi, "freq": 0, "band": band, "channel": ch, "security": sec, "bssid": ""})
                if nets:
                    return nets
            except Exception:
                pass

        # Linux fallback (nmcli)
        if system == "Linux":
            try:
                out = run_cmd(["nmcli", "-f", "SSID,SIGNAL,FREQ,CHAN,SECURITY,BSSID", "device", "wifi", "list"], timeout=4)
                lines = out.strip().splitlines()
                for ln in lines[1:] if len(lines) > 1 and "SSID" in lines[0] else lines:
                    parts = [p.strip() for p in ln.split(":")] if ":" in ln else re.split(r'\s{2,}', ln.strip())
                    # some nmcli outputs may include BSSID as extra column; attempt to parse robustly
                    if len(parts) >= 5:
                        ssid = parts[0] or "<hidden>"
                        rssi = int(parts[1]) if parts[1].isdigit() else -100
                        freq = float(parts[2]) if re.match(r'^\d+(\.\d+)?$', parts[2]) else 0
                        ch = int(parts[3]) if parts[3].isdigit() else channel_from_freq(freq)
                        sec = parts[4] or "Unknown"
                        bssid = parts[5] if len(parts) > 5 else ""
                        band = freq_band(freq)
                        nets.append({"ssid": ssid, "rssi": rssi, "freq": freq, "band": band, "channel": ch, "security": parse_security(sec), "bssid": bssid})
                if nets:
                    return nets
            except Exception:
                pass

        # Windows fallback (netsh)
        if system == "Windows":
            try:
                out = run_cmd(["netsh", "wlan", "show", "networks", "mode=Bssid"], timeout=4)

                ssid_map = {}
                current_ssid = None
                current_sec = "Unknown"
                current_rssi = None
                current_channel = None

                # We'll try to capture BSSID lines where available
                last_bssid = ""

                for line in out.splitlines():
                    ln = line.strip()

                    m_ssid = re.match(r'^SSID\s+\d+\s*:\s*(.+)$', ln)
                    if m_ssid:
                        current_ssid = m_ssid.group(1).strip() or "<hidden>"
                        current_sec = "Unknown"
                        current_rssi = None
                        current_channel = None
                        last_bssid = ""
                        if current_ssid not in ssid_map:
                            ssid_map[current_ssid] = {"ssid": current_ssid, "rssi": -100, "freq": 0, "band": "", "channel": 0, "security": "Unknown", "bssid": ""}
                        continue

                    if current_ssid:
                        m_auth = re.match(r'^Authentication\s*:\s*(.+)$', ln)
                        if m_auth:
                            current_sec = parse_security(m_auth.group(1))
                            ssid_map[current_ssid]["security"] = current_sec
                            continue

                        m_sig = re.match(r'^Signal\s*:\s*([0-9]{1,3})%', ln)
                        if m_sig:
                            percent = int(m_sig.group(1))
                            current_rssi = int(percent / 2 - 100)
                            continue

                        m_bssid = re.match(r'^BSSID\s+\d+\s*:\s*(.+)$', ln)
                        if m_bssid:
                            last_bssid = m_bssid.group(1).strip()
                            ssid_map[current_ssid]["bssid"] = last_bssid
                            continue

                        m_channel = re.match(r'^Channel\s*:\s*(\d+)$', ln)
                        if m_channel:
                            current_channel = int(m_channel.group(1))
                            if current_rssi is None:
                                current_rssi = -100
                            if current_rssi > ssid_map[current_ssid]["rssi"]:
                                band = "2.4 GHz" if current_channel <= 14 else ("5 GHz" if current_channel < 200 else "6 GHz")
                                ssid_map[current_ssid].update({
                                    "rssi": current_rssi,
                                    "channel": current_channel,
                                    "band": band
                                })
                            current_rssi = None
                            current_channel = None
                            continue

                nets = list(ssid_map.values())
                return nets
            except Exception:
                pass

        return nets

# ---------------------------
# WIFI PROFILES (PASSWORDS)
# ---------------------------
class WifiProfiles:
    @staticmethod
    def _windows_show_profile(raw_profile):
        """
        Retrieve password + security for a given Wi-Fi profile on Windows.
        Uses the raw profile name exactly as returned by `netsh wlan show profiles`,
        so trailing spaces and special characters are preserved.
        """
        try:
            cmd = f'netsh wlan show profile name="{raw_profile}" key=clear'
            detail = run_cmd(cmd, timeout=4, shell=True)

            # Capture full Key Content line
            match = re.search(r"^\s*Key Content\s*:.*$", detail, re.MULTILINE)
            if match:
                line = match.group(0).strip()
                password = line.split(":", 1)[1].strip()
            else:
                password = ""

            # Capture Authentication type
            sec_match = re.search(r"^\s*Authentication\s*:\s*(.+)$", detail, re.MULTILINE)
            security = sec_match.group(1).strip() if sec_match else ""

            return password, security
        except Exception:
            return "", ""

    @staticmethod
    def _windows_export_and_parse(ssid):
        try:
            temp_dir = os.path.join(os.environ.get("TEMP", os.getcwd()))
            # Export XML with key material. Use shell string because netsh export sometimes expects quoted args.
            cmd = f'netsh wlan export profile name="{ssid}" key=clear folder="{temp_dir}"'
            _ = run_cmd(cmd, timeout=6, shell=True)

            # Find exported xml for the ssid
            xml_file = None
            for fname in os.listdir(temp_dir):
                if fname.lower().endswith(".xml") and ssid.lower() in fname.lower():
                    xml_file = os.path.join(temp_dir, fname)
                    break
            password = ""
            security = ""
            if xml_file and os.path.isfile(xml_file):
                with open(xml_file, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                m_pwd = re.search(r"<keyMaterial>(.+?)</keyMaterial>", content, re.S)
                password = m_pwd.group(1).strip() if m_pwd else ""
                m_sec = re.search(r"<authentication>(.+?)</authentication>", content, re.S)
                security = m_sec.group(1).strip() if m_sec else ""
                try:
                    os.remove(xml_file)
                except Exception:
                    pass
            return password, security
        except Exception:
            return "", ""

    @staticmethod
    def list_with_passwords():
        system = platform.system()
        results = []
        try:
            if system == "Windows":
                base = run_cmd(["netsh", "wlan", "show", "profiles"], timeout=4)
                profiles = []
                for ln in base.splitlines():
                    m = re.search(r"^\s*All User Profile\s*:\s*(.+)\s*$", ln)
                    if m:
                        profiles.append(m.group(1))
                for raw_profile in profiles:
                    clean_name = raw_profile.strip()
                    password, security = WifiProfiles._windows_show_profile(raw_profile)
                    if not password:
                        password, sec2 = WifiProfiles._windows_export_and_parse(raw_profile)
                        if sec2 and not security:
                            security = sec2
                    results.append({
                        "ssid": clean_name,
                        "password": password,
                        "security": security
                    })

            elif system == "Darwin":
                try:
                    out = run_cmd(["/usr/sbin/networksetup", "-listpreferredwirelessnetworks", "en0"], timeout=4)
                    ssids = [ln.strip() for ln in out.splitlines()
                             if ln.strip() and not ln.strip().startswith("Preferred networks")]
                except Exception:
                    ssids = []
                for ssid in ssids:
                    password = ""
                    security = ""
                    try:
                        cmd = ["security", "find-generic-password", "-D", "AirPort network password", "-ga", ssid]
                        p = subprocess.Popen(cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
                        _, err = p.communicate(timeout=4)
                        m = re.search(r'password:\s*"(.+)"', err.decode(errors="ignore"))
                        password = m.group(1) if m else ""
                    except Exception:
                        pass
                    results.append({"ssid": ssid, "password": password, "security": security})

            elif system == "Linux":
                base_dir = "/etc/NetworkManager/system-connections"
                if os.path.isdir(base_dir):
                    for fname in os.listdir(base_dir):
                        path = os.path.join(base_dir, fname)
                        ssid = ""
                        password = ""
                        security = ""
                        try:
                            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                                content = f.read()
                            m_ssid = re.search(r'^ssid=(.+)$', content, re.M)
                            m_pwd = re.search(r'^psk=(.+)$', content, re.M)
                            m_sectype = re.search(r'^\[wifi-security\]\n.*?key-mgmt=(.+)$', content, re.M | re.S)
                            ssid = m_ssid.group(1).strip() if m_ssid else fname
                            password = m_pwd.group(1).strip() if m_pwd else ""
                            security = m_sectype.group(1).strip() if m_sectype else ""
                        except Exception:
                            pass
                        results.append({"ssid": ssid, "password": password, "security": security})
        except Exception:
            pass
        return results

# ---------------------------
# MATPLOTLIB CANVASES
# ---------------------------
class SignalCanvas(FigureCanvas):
    COLORS = [
        "#59A5D8", "#FF7F50", "#8AFF80", "#FFD166", "#EF476F", "#9B5DE5",
        "#06D6A0", "#118AB2", "#F4A261", "#4ECDC4"
    ]

    def __init__(self, parent=None):
        fig = Figure(figsize=(5, 3), tight_layout=True)
        super().__init__(fig)
        self.ax = fig.add_subplot(111)
        self._style_axes()
        self.lines = {}
        self.buffers = defaultdict(lambda: [])
        self.max_points = 120
        self.color_idx = 0

    def _style_axes(self):
        self.ax.set_title("Signal strength (RSSI over time)", color="#EEE")
        self.ax.set_xlabel("Time", color="#BBB")
        self.ax.set_ylabel("dBm", color="#BBB")
        self.ax.grid(True, linestyle="--", alpha=0.25, color="#AAA")
        self.ax.set_facecolor("#1b1b1d")
        self.figure.patch.set_facecolor("#1b1b1d")
        for spine in self.ax.spines.values():
            spine.set_color("#555")
        self.ax.tick_params(colors="#BBB")
        # legend may be empty initially — guard it
        if self.ax.get_legend() is not None:
            leg = self.ax.legend(loc="upper left", fontsize=8, frameon=False)
            for text in leg.get_texts():
                text.set_color("#ff00d0")

    def update_series(self, ssid, rssi):
        buf = self.buffers[ssid]
        buf.append((datetime.now(), rssi))
        if len(buf) > self.max_points:
            buf.pop(0)
        xs = [b[0] for b in buf]
        ys = [b[1] for b in buf]
        if ssid not in self.lines:
            color = self.COLORS[self.color_idx % len(self.COLORS)]
            self.color_idx += 1
            line, = self.ax.plot(xs, ys, label=ssid, color=color, linewidth=1.6)
            self.lines[ssid] = line
            self.ax.legend(loc="upper left", fontsize=8, frameon=False)
        else:
            self.lines[ssid].set_xdata(xs)
            self.lines[ssid].set_ydata(ys)
        self.ax.relim()
        self.ax.autoscale_view()
        self.draw_idle()

class ChannelCanvas(FigureCanvas):
    def __init__(self, parent=None):
        fig = Figure(figsize=(5, 3), tight_layout=True)
        super().__init__(fig)
        self.ax = fig.add_subplot(111)
        self._style_axes()

    def _style_axes(self):
        self.ax.set_title("Channel utilization", color="#EEE")
        self.ax.set_xlabel("Channel", color="#BBB")
        self.ax.set_ylabel("Relative occupancy", color="#BBB")
        self.ax.grid(True, linestyle="--", alpha=0.25, color="#AAA")
        self.ax.set_facecolor("#1b1b1d")
        self.figure.patch.set_facecolor("#1b1b1d")
        for spine in self.ax.spines.values():
            spine.set_color("#555")
        self.ax.tick_params(colors="#BBB")

    def update_bars(self, channel_counts):
        self.ax.clear()
        self._style_axes()
        chs = sorted(channel_counts.keys())
        vals = [channel_counts[ch] for ch in chs]
        self.ax.bar(chs, vals, color="#4C78A8")
        self.draw_idle()

# ---------------------------
# TABS / UI
# ---------------------------

def make_readonly_item(text):
    """Helper to create a read-only QTableWidgetItem."""
    item = QTableWidgetItem(text)
    item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
    return item

class LANTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)

        controls = QHBoxLayout()
        self.scan_btn = QPushButton("Scan 192.168.*.*")
        self.stop_btn = QPushButton("Stop")
        self.progress = QProgressBar()
        controls.addWidget(QLabel("LAN Device Scanner"))
        controls.addStretch(1)
        controls.addWidget(self.scan_btn)
        controls.addWidget(self.stop_btn)
        controls.addWidget(self.progress)
        layout.addLayout(controls)

        # Add tip about internet requirement for vendor lookup
        self.hint = QLabel("Tip: Internet connection is required to resolve MAC vendors (online lookup).")
        self.hint.setStyleSheet("color: #9aa0a6; padding: 4px;")
        layout.addWidget(self.hint)

        # Add table: include an extra column for a copy button
        self.table = QTableWidget(0, 5)
        self.table.setAlternatingRowColors(True)
        self.table.setHorizontalHeaderLabels(["IP address", "MAC address", "Vendor", "Device model", "📋"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.table)

        self.scan_btn.clicked.connect(self.start_scan)
        
        self.stop_btn.clicked.connect(self.stop_scan)

        self.thread = None

    def start_scan(self):
        self.scan_btn.setStyleSheet("background-color: #24a343; color: #03fccf;")
        self.table.setRowCount(0)
        cidrs = local_ipv4_candidates()
        expanded = []
        for _ in cidrs:
            base = "192.168"
            for third in range(0, 256):
                expanded.append(f"{base}.{third}.0/24")
        self.thread = LANScannerThread(expanded)
        self.thread.found.connect(self.add_row)
        self.thread.progress.connect(self.progress.setValue)
        self.thread.done.connect(lambda: QMessageBox.information(self, "Done", "LAN scan completed"))
        self.thread.start()

    def stop_scan(self):
        self.scan_btn.setStyleSheet("background-color: #4C78A8; color: #ffffff;")
        if self.thread:
            self.thread.stop()

    def add_row(self, dev):
        r = self.table.rowCount()
        self.table.insertRow(r)
        ip_item = make_readonly_item(dev.get("ip", ""))
        mac_item = make_readonly_item(dev.get("mac", ""))
        vendor_item = make_readonly_item(dev.get("vendor", ""))
        model_item = make_readonly_item(dev.get("model", ""))

        self.table.setItem(r, 0, ip_item)
        self.table.setItem(r, 1, mac_item)
        self.table.setItem(r, 2, vendor_item)
        self.table.setItem(r, 3, model_item)

        # Copy button column
        btn = QPushButton("📋")
        btn.setToolTip("Copy MAC address")
        btn.clicked.connect(partial(self.copy_mac_from_row, r))
        # style small
        btn.setMaximumWidth(48)
        self.table.setCellWidget(r, 4, btn)

    def copy_mac_from_row(self, row):
        item = self.table.item(row, 1)
        if item:
            QApplication.clipboard().setText(item.text())
            QMessageBox.information(self, "Copied", "MAC address copied to clipboard")

class WifiProfilesTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)

        controls = QHBoxLayout()
        controls.addWidget(QLabel("Wi-Fi Saved Passwords"))
        controls.addStretch(1)
        self.refresh_btn = QPushButton("Refresh")
        controls.addWidget(self.refresh_btn)
        layout.addLayout(controls)

        self.table = QTableWidget(0, 4)
        self.table.setAlternatingRowColors(True)
        self.table.setHorizontalHeaderLabels(["SSID", "Password", "Security", "Actions"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.table)

        self.refresh_btn.clicked.connect(self.refresh)

        self.hint = QLabel("Tip: On Windows, run the app as Administrator to reveal saved passwords.")
        self.hint.setStyleSheet("color: #9aa0a6; padding: 4px;")
        layout.addWidget(self.hint)

    def refresh(self):
        self.refresh_btn.setStyleSheet("background-color: #24a343; color: #03fccf;")
        QApplication.processEvents() 
        self.table.setRowCount(0)
        profiles = WifiProfiles.list_with_passwords()
        for p in profiles:
            r = self.table.rowCount()
            self.table.insertRow(r)
            self.table.setItem(r, 0, make_readonly_item(p.get("ssid", "")))
            self.table.setItem(r, 1, make_readonly_item(p.get("password", "")))
            self.table.setItem(r, 2, make_readonly_item(p.get("security", "")))
            btn = QPushButton("Copy")
            btn.clicked.connect(lambda _, row=r: self.copy_password(row))
            self.table.setCellWidget(r, 3, btn)
        QTimer.singleShot(100, lambda: self.refresh_btn.setStyleSheet(
        "background-color: #4C78A8; color: #ffffff;"
    ))
    def copy_password(self, row):
        pwd_item = self.table.item(row, 1)
        if pwd_item:
            QApplication.clipboard().setText(pwd_item.text())
            QMessageBox.information(self, "Copied", "Password copied to clipboard")

class WifiAnalyzerTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)

        controls = QHBoxLayout()
        controls.addWidget(QLabel("Wi-Fi Analyzer"))
        controls.addStretch(1)
        self.start_btn = QPushButton("Start")
        self.stop_btn = QPushButton("Stop")
        self.band_filter = QComboBox()
        self.band_filter.addItems(["All", "2.4 GHz", "5 GHz", "6 GHz"])
        controls.addWidget(QLabel("Band filter:"))
        controls.addWidget(self.band_filter)
        controls.addWidget(self.start_btn)
        controls.addWidget(self.stop_btn)
        layout.addLayout(controls)

        # Tip about internet requirement for vendor lookup (so user knows vendor resolution depends on internet)
        self.hint = QLabel("Tip: Internet connection is required to resolve MAC vendors (online lookup).")
        self.hint.setStyleSheet("color: #9aa0a6; padding: 4px;")
        layout.addWidget(self.hint)

        splitter = QSplitter(Qt.Vertical)
        # Add an extra hidden column for BSSID (MAC) + a copy column
        self.table = QTableWidget(0, 8)
        self.table.setAlternatingRowColors(True)
        self.table.setHorizontalHeaderLabels([
            "SSID", "Signal (dBm)", "Band", "Channel", "Frequency (MHz)", "Security", "BSSID (MAC)", "📋"
        ])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        splitter.addWidget(self.table)

        charts = QWidget()
        charts_layout = QHBoxLayout(charts)
        self.signal_canvas = SignalCanvas()
        self.channel_canvas = ChannelCanvas()
        charts_layout.addWidget(self.signal_canvas, 2)
        charts_layout.addWidget(self.channel_canvas, 1)
        splitter.addWidget(charts)
        layout.addWidget(splitter)

        self.thread = None
        self.last_scan = []

        self.start_btn.clicked.connect(self.start)
        self.stop_btn.clicked.connect(self.stop)
        self.band_filter.currentTextChanged.connect(self.refresh_table_only)

    def start(self):
        if self.thread:
            return
        self.thread = WifiScannerThread(interval_ms=1500)
        self.thread.updated.connect(self.update_scan)
        self.thread.start()

    def stop(self):
        if self.thread:
            self.thread.stop()
            self.thread.wait()
            self.thread = None

    def update_scan(self, nets):
        self.last_scan = nets
        self.refresh_table_only()
        channel_counts = defaultdict(int)
        filt = self.band_filter.currentText()
        for n in nets:
            ssid = n["ssid"]
            rssi = n["rssi"]
            ch = n["channel"]
            band = n["band"]
            if filt == "All" or band == filt:
                self.signal_canvas.update_series(ssid, rssi)
                if ch:
                    channel_counts[ch] += 1
        self.channel_canvas.update_bars(channel_counts)

    def refresh_table_only(self):
        filt = self.band_filter.currentText()
        self.table.setRowCount(0)
        for n in self.last_scan:
            if filt != "All" and n["band"] != filt:
                continue
            r = self.table.rowCount()
            self.table.insertRow(r)
            self.table.setItem(r, 0, make_readonly_item(n.get("ssid", "")))
            self.table.setItem(r, 1, make_readonly_item(str(n.get("rssi", ""))))
            self.table.setItem(r, 2, make_readonly_item(n.get("band", "")))
            self.table.setItem(r, 3, make_readonly_item(str(n.get("channel", ""))))
            self.table.setItem(r, 4, make_readonly_item(str(n.get("freq", ""))))
            self.table.setItem(r, 5, make_readonly_item(n.get("security", "")))
            # BSSID (MAC) column - may be empty if unavailable
            bssid = n.get("bssid", "") or ""
            self.table.setItem(r, 6, make_readonly_item(bssid))
            # Copy button column
            btn = QPushButton("📋")
            btn.setToolTip("Copy MAC (BSSID)")
            btn.setMaximumWidth(48)
            btn.clicked.connect(partial(self.copy_mac_from_row, r))
            self.table.setCellWidget(r, 7, btn)

    def copy_mac_from_row(self, row):
        item = self.table.item(row, 6)
        if item:
            mac = item.text()
            QApplication.clipboard().setText(mac)
            QMessageBox.information(self, "Copied", "MAC (BSSID) copied to clipboard")

# ---------------------------
# MAIN WINDOW
# ---------------------------
class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"🔍{APP_NAME} ")
        # update icon path if needed
        self.setWindowIcon(QIcon("D:\\wifi-icon-3782-Windows.ico"))
        self.resize(1150, 750)
        layout = QVBoxLayout(self)
        tabs = QTabWidget()
        tabs.addTab(LANTab(), "LAN Device Scanner")
        tabs.addTab(WifiProfilesTab(), "Wi-Fi Saved Passwords")
        tabs.addTab(WifiAnalyzerTab(), "Wi-Fi Analyzer")
        layout.addWidget(tabs)

def main():
    app = QApplication(sys.argv)
    apply_dark_theme(app)
    w = MainWindow()
    w.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
