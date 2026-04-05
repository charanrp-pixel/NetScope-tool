import socket
import struct
import platform
import subprocess
from concurrent.futures import ThreadPoolExecutor

try:
    from scapy.all import IP, TCP, sr1, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

COMMON_PORTS = {
    21: "FTP Server",
    22: "SSH Server",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP Web Server",
    111: "RPCBind",
    135: "Windows RPC",
    139: "NetBIOS",
    443: "HTTPS Web Server",
    445: "Windows SMB",
    515: "LPD Printer",
    554: "RTSP IP Camera",
    631: "IPP Printer",
    3306: "MySQL Database",
    3389: "RDP Remote Desktop",
    5000: "UPnP / Flask",
    8000: "Web Service",
    8080: "HTTP Proxy/Web",
    9100: "JetDirect Printer",
}

def guess_os_from_ttl_window(ttl: int, window: int) -> str:
    """Guess OS based on ping/TCP TTL and TCP Window size heuristics."""
    if ttl <= 64:
        if window in (65535, 4128):
            return "macOS / iOS / FreeBSD"
        elif window == 5840 or window < 30000:
            return "Linux / Android"
        return "Linux / Unix-like"
    elif ttl <= 128:
        return "Windows PC/Server"
    elif ttl <= 255:
        return "Network Appliance / Router / Cisco"
    return "Unknown OS"

def active_os_fingerprint(ip: str, open_ports: list) -> str:
    """Send a TCP SYN to an open port and analyze the SYN-ACK response for OS fingerprinting."""
    if not SCAPY_AVAILABLE or not open_ports:
        return "Unknown (Requires Scapy & Open Port)"
    
    test_port = open_ports[0]
    try:
        # Keep scapy quiet
        conf.verb = 0
        pkt = IP(dst=ip)/TCP(dport=test_port, flags="S")
        ans = sr1(pkt, timeout=1, verbose=0)
        
        if ans and ans.haslayer(TCP) and ans.haslayer(IP):
            # Check if it's a SYN-ACK
            if ans[TCP].flags & 0x12:
                ttl = ans[IP].ttl
                window = ans[TCP].window
                return guess_os_from_ttl_window(ttl, window)
    except Exception:
        pass
        
    return "Unknown / Unresponsive"

def guess_device_type(vendor: str, open_ports: list, os_guess: str) -> str:
    """Heuristic logic to guess device type based on vendor, open ports, and OS."""
    vendor_lower = (vendor or "").lower()
    ports_set = set(open_ports or [])
    
    # Check by open ports first (most reliable functional indicator)
    if 515 in ports_set or 631 in ports_set or 9100 in ports_set:
        return "Printer / Scanner"
    if 554 in ports_set:
        return "IP Camera / Surveillance"
    if 135 in ports_set or 445 in ports_set or 3389 in ports_set:
        return "Desktop / Server (Windows)"
    
    # Check by vendor
    if "apple" in vendor_lower:
        return "iPhone / iPad / Mac / Apple TV"
    if "samsung" in vendor_lower:
        return "Samsung Phone / Smart TV / Tablet"
    if "espressif" in vendor_lower or "shenzhen" in vendor_lower or "tuya" in vendor_lower:
        return "IoT Smart Device (Bulb/Plug)"
    if "raspberry" in vendor_lower:
        return "Raspberry Pi"
    if "cisco" in vendor_lower or "netgear" in vendor_lower or "tp-link" in vendor_lower or "ubiquiti" in vendor_lower:
        return "Router / Switch / Access Point"
    if "sony" in vendor_lower or "nintendo" in vendor_lower:
        return "Gaming Console"
    if "google" in vendor_lower:
        return "Chromecast / Google Home / Android"
        
    # Check by OS
    if "Windows" in os_guess:
        return "Windows PC"
    if "macOS" in os_guess:
        return "Apple Device"
        
    return "Generic Endpoint"

def grab_banner(ip: str, port: int) -> str:
    """Connect to a port and grab the service banner."""
    try:
        s = socket.socket()
        s.settimeout(1.0)
        s.connect((ip, port))
        
        # If it's HTTP, send a basic GET to trigger a Server header response
        if port in (80, 443, 8080):
            s.send(b"GET / HTTP/1.0\r\n\r\n")
            
        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        s.close()
        
        # Parse out headers if HTTP
        if "HTTP" in banner and "Server:" in banner:
            for line in banner.split("\n"):
                if line.lower().startswith("server:"):
                    return line.strip()
                    
        # Return first line of basic text banner
        if banner:
            return banner.split("\n")[0][:100]
    except Exception:
        pass
    return ""

def profile_device(ip: str, mac: str, vendor: str, open_ports: list) -> dict:
    """Run deeper analysis on a single device."""
    open_ports = open_ports or []
    
    # 1. OS Fingerprinting
    os_info = active_os_fingerprint(ip, open_ports)
    
    # 2. Device Type Guessing
    dev_type = guess_device_type(vendor, open_ports, os_info)
    
    # 3. Port specific services & banners
    services = []
    
    def check_port(port):
        name = COMMON_PORTS.get(port, "Unknown Service")
        banner = grab_banner(ip, port)
        return {"port": port, "name": name, "banner": banner}
        
    with ThreadPoolExecutor(max_workers=min(10, len(open_ports)+1)) as executor:
        futures = [executor.submit(check_port, p) for p in open_ports]
        for f in futures:
            services.append(f.result())
            
    services.sort(key=lambda x: x["port"])

    return {
        "ip": ip,
        "mac": mac or "Unknown",
        "vendor": vendor or "Unknown",
        "os": os_info,
        "device_type": dev_type,
        "services": services
    }
