# NetScope

A network analysis dashboard inspired by Wireshark. Discover devices on your LAN, view IP/MAC/vendor, risk scores, and export reports.

**Tech stack:** Python, Scapy, Flask.

## Features

- **Device discovery** – ARP scan to list devices on the same network
- **Per-device info** – IP, MAC, device name (when available), vendor (OUI lookup)
- **Packet statistics** – Simulated sent/received counts per device
- **Risk score** – Based on open ports (e.g. many open ports = medium/high risk)
- **Topology view** – Simple graph of devices and gateway
- **PDF export** – Download a scan report as PDF

## Setup

```bash
cd /Users/jraghu/Downloads/Wireshark
python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

**Note:** Scapy needs raw socket access for ARP. On **Linux** run with `sudo python app.py` (or set capabilities) or the scan may find no devices. On **macOS** it often works as a normal user. If you see only "this machine", run with administrator privileges.

## Run

```bash
# From project root, with venv activated
python app.py
```

Open http://127.0.0.1:5000 in your browser.

## Usage

1. Click **Use my network** to fill in your local CIDR (e.g. `192.168.1.0/24`).
2. Optionally enable/disable **Port scan** (used for risk score).
3. Click **Scan network** to discover devices.
4. Check **Devices** table for IP, MAC, vendor, risk, open ports, and packet stats.
5. View **Network topology** for a simple graph.
6. Use **Download scan report (PDF)** to export the current device list.

## Project layout

```
.
├── app.py              # Flask app and API routes
├── config.py           # Timeouts, risk thresholds, ports
├── network_scanner.py  # Scapy ARP scan, vendor lookup, port scan
├── pdf_export.py       # PDF report generation
├── requirements.txt
├── README.md
├── static/
│   ├── css/style.css
│   └── js/app.js
└── templates/
    ├── base.html
    └── index.html
```

## License

Use and modify as you like.
