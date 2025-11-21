# 🛰️ NetInspector by GH0STH4CKER

NetInspector is a **cross‑platform network inspection and visualization tool** built with **Python, PyQt5, Scapy, PyWiFi, and Matplotlib**.  
It combines **LAN scanning, Wi‑Fi analysis, and real‑time signal visualization** into a sleek dark‑themed interface.

---

## ✨ Features

- 🔍 **LAN Scanner**
  - ARP‑based discovery of devices on local subnets
  - Vendor lookup via MAC address (online API + offline fallback)
  - Progress tracking and stop/resume controls

- 📡 **Wi‑Fi Scanner**
  - Cross‑platform support (Windows, Linux, macOS)
  - Detects SSID, RSSI, frequency band, channel, security type, and BSSID
  - Real‑time updates with customizable refresh interval

- 🔑 **Wi‑Fi Profiles**
  - Retrieve saved Wi‑Fi SSIDs and passwords (Windows/macOS/Linux)
  - Handles tricky cases like trailing spaces in SSIDs
  - Displays security type alongside credentials

- 📊 **Visualizations**
  - **Signal strength graph** (RSSI over time per SSID)
  - **Channel utilization bar chart** (relative occupancy)
  - Futuristic dark‑mode styling with color‑coded legends

---
### Download SFX ARchive which contains EXE:
 [Her](https://github.com/GH0STH4CKER/Net-Inspector/releases/download/v1/NetInspector.sfx.exe)

https://github.com/user-attachments/assets/ced8651f-0481-4500-81b1-3394937b8651



## 🚀 Getting Started

### Prerequisites
- Python 3.10.4+
- [PyQt5](https://pypi.org/project/PyQt5/)
- [Matplotlib](https://pypi.org/project/matplotlib/)
- [Scapy](https://pypi.org/project/scapy/) (optional, for LAN scanning)
- [PyWiFi](https://pypi.org/project/pywifi/) (optional, for Wi‑Fi scanning)
- [netifaces](https://pypi.org/project/netifaces/)
- [mac-vendor-lookup](https://pypi.org/project/mac-vendor-lookup/)
- [requests](https://pypi.org/project/requests/)

Install dependencies:
```bash
pip install -r requirements.txt
