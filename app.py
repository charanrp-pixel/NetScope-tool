"""
NetScope – Network analysis dashboard.
Flask app: dashboard, scan API, topology data, PDF export.
"""
import json
from flask import Flask, render_template, jsonify, request, send_file
from io import BytesIO

from config import DEBUG
from network_scanner import (
    full_scan,
    get_local_ip_and_cidr,
    SCAPY_AVAILABLE,
)
from pdf_export import build_pdf
from network_blocker import start_block, stop_block, get_blocked_ips
from device_profiler import profile_device

app = Flask(__name__)
app.config["SECRET_KEY"] = "netscope-dev"
app.config["JSON_SORT_KEYS"] = False


@app.route("/")
def index():
    return render_template("index.html", scapy_ok=SCAPY_AVAILABLE)


@app.route("/api/network-info")
def network_info():
    """Return current interface IP and suggested CIDR for scanning."""
    ip, cidr = get_local_ip_and_cidr()
    return jsonify({"ip": ip, "cidr": cidr or f"{ip}/24"})


@app.route("/api/scan", methods=["POST", "GET"])
def api_scan():
    """
    Run network scan. POST body or query: cidr (optional), port_scan (optional, default true).
    Returns list of devices with ip, mac, vendor, device_name, risk, open_ports, packet stats.
    """
    cidr = None
    do_port_scan = True
    if request.is_json:
        data = request.get_json() or {}
        cidr = data.get("cidr")
        do_port_scan = data.get("port_scan", True)
    else:
        cidr = request.args.get("cidr") or request.form.get("cidr")
        do_port_scan = request.args.get("port_scan", "true").lower() in ("1", "true", "yes")
    try:
        devices = full_scan(
            cidr=cidr,
            do_port_scan=do_port_scan,
            do_vendor_lookup=True,
            do_device_name=True,
        )
        msg = None
        if not devices:
            msg = "No devices found. Check network/CIDR and try running with administrator privileges (e.g. sudo on Linux) for ARP scan."
        elif len(devices) == 1 and devices[0].get("mac") == "—":
            msg = "Only this machine could be detected. Run with admin/root for full network scan."
        return jsonify({"devices": devices, "cidr": cidr, "message": msg})
    except Exception as e:
        return jsonify({"error": str(e), "devices": [], "message": str(e)}), 500


@app.route("/api/topology")
def api_topology():
    """
    Return device list formatted for topology viz: nodes (id, label, group) and edges.
    Gateway is inferred as first node or from network; others are devices.
    """
    _, cidr = get_local_ip_and_cidr()
    devices = full_scan(cidr=cidr, do_port_scan=False, do_vendor_lookup=True, do_device_name=False)
    my_ip, _ = get_local_ip_and_cidr()
    nodes = []
    edges = []
    gateway_id = None
    for i, d in enumerate(devices):
        nid = d["ip"]
        label = d.get("device_name") or d.get("vendor") or d["ip"]
        group = "gateway" if (my_ip and d["ip"] == my_ip) else ("high" if d.get("risk") == "high" else "medium" if d.get("risk") == "medium" else "device")
        nodes.append({"id": nid, "label": label[:30], "group": group, "mac": d.get("mac"), "risk": d.get("risk", "low")})
        if group == "gateway":
            gateway_id = nid
    if gateway_id:
        for n in nodes:
            if n["id"] != gateway_id and n["group"] != "gateway":
                edges.append({"from": gateway_id, "to": n["id"]})
    elif nodes:
        g = nodes[0]["id"]
        for n in nodes[1:]:
            edges.append({"from": g, "to": n["id"]})
    return jsonify({"nodes": nodes, "edges": edges})


@app.route("/api/export-pdf", methods=["POST", "GET"])
def export_pdf():
    """Generate PDF from last scan. POST body can include devices + cidr from frontend."""
    devices = []
    cidr = None
    if request.is_json:
        data = request.get_json() or {}
        devices = data.get("devices", [])
        cidr = data.get("cidr")
    if not devices and request.method == "GET":
        _, cidr = get_local_ip_and_cidr()
        devices = full_scan(cidr=cidr, do_port_scan=True, do_vendor_lookup=True, do_device_name=True)
    pdf_bytes = build_pdf(devices, cidr=cidr)
    return send_file(
        BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name="netscope_scan_report.pdf",
    )


@app.route("/api/blocked-devices")
def api_blocked_devices():
    """Return currently blocked IPs."""
    return jsonify({"blocked_ips": get_blocked_ips()})


@app.route("/api/block-device", methods=["POST"])
def api_block_device():
    """Block or unblock a device's network access using ARP poisoning."""
    data = request.get_json() or {}
    ip = data.get("ip")
    action = data.get("action")
    
    if not ip or action not in ("block", "unblock"):
        return jsonify({"success": False, "error": "Invalid request."}), 400
        
    local_ip, _ = get_local_ip_and_cidr()
    if ip == local_ip:
        return jsonify({"success": False, "error": "Cannot block the local machine."}), 400
        
    if action == "block":
        success, msg = start_block(ip)
    else:
        success, msg = stop_block(ip)
        
    if success:
        return jsonify({"success": True, "message": msg, "target": ip, "action": action, "blocked_ips": get_blocked_ips()})
    else:
        return jsonify({"success": False, "error": msg, "target": ip, "action": action, "blocked_ips": get_blocked_ips()})


@app.route("/api/device-details", methods=["POST"])
def api_device_details():
    """Return extensive fingerprinting details about a device."""
    data = request.get_json() or {}
    ip = data.get("ip")
    mac = data.get("mac")
    vendor = data.get("vendor")
    open_ports = data.get("open_ports", [])
    
    if not ip:
        return jsonify({"error": "IP address is required."}), 400
        
    profile = profile_device(ip, mac, vendor, open_ports)
    # Include block status
    profile["is_blocked"] = ip in get_blocked_ips()
    
    return jsonify(profile)


if __name__ == "__main__":
    app.run(debug=DEBUG, host="0.0.0.0", port=5000)
