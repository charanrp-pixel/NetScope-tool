"""
Network scanner using Scapy.
Discovers devices via ARP, resolves vendor, optional port scan for risk.
"""
from __future__ import annotations

import socket
import subprocess
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

from netaddr import IPNetwork

try:
    from scapy.all import ARP, Ether, srp, get_if_list, conf
    from scapy.config import conf as scapy_conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    from mac_vendor_lookup import MacLookup
    MAC_LOOKUP_AVAILABLE = True
except ImportError:
    MAC_LOOKUP_AVAILABLE = False

from config import (
    SCAN_TIMEOUT,
    PORT_SCAN_PORTS,
    PORT_SCAN_TIMEOUT,
    RISK_LOW,
    RISK_MEDIUM,
    RISK_HIGH,
    OPEN_PORTS_MEDIUM_THRESHOLD,
    OPEN_PORTS_HIGH_THRESHOLD,
)


def get_default_interface() -> Optional[str]:
    """Try to get the default network interface (e.g. en0 on macOS)."""
    if not SCAPY_AVAILABLE:
        return None
    try:
        ifs = get_if_list()
        # Prefer common names
        for name in ("en0", "eth0", "wlan0", "en1"):
            if name in ifs:
                return name
        return ifs[0] if ifs else None
    except Exception:
        return None


def _socket_get_local_ip() -> Optional[str]:
    """Get local IP via socket (works without Scapy)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None


def _ip_to_network_cidr(ip: str, prefix_len: int = 24) -> str:
    """Convert host IP to network CIDR (e.g. 192.168.1.5 -> 192.168.1.0/24)."""
    try:
        net = IPNetwork(f"{ip}/{prefix_len}")
        return str(net.network) + f"/{prefix_len}"
    except Exception:
        return f"{ip}/24"


def get_local_ip_and_cidr() -> tuple[Optional[str], Optional[str]]:
    """Get local IP and network CIDR for scanning (e.g. 192.168.1.0/24)."""
    ip = None
    if SCAPY_AVAILABLE:
        try:
            iface = get_default_interface()
            if iface:
                routes = conf.route.routes
                for route in routes:
                    if route[3] == iface and route[0] != 0:
                        ip = route[4]
                        if ip and ip != "0.0.0.0":
                            ip = str(ip)
                            break
        except Exception:
            pass
    if not ip:
        ip = _socket_get_local_ip()
    if not ip:
        return None, None
    cidr = _ip_to_network_cidr(ip)
    return ip, cidr


def _arp_scan_scapy(cidr: str, timeout: float, iface: Optional[str]) -> list[dict]:
    """Run ARP scan by sending one request per IP in the subnet (works reliably)."""
    try:
        net = IPNetwork(cidr)
        network_cidr = str(net.network) + f"/{net.prefixlen}"
    except Exception:
        network_cidr = cidr
        net = IPNetwork(cidr)
    # Build one packet per host (skip network and broadcast)
    hosts = [str(ip) for ip in net.iter_hosts()]
    if not hosts:
        return []
    packets = [
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        for ip in hosts
    ]
    kwargs = {"timeout": timeout, "inter": 0.05}
    if iface:
        kwargs["iface"] = iface
    try:
        ans, _ = srp(packets, **kwargs)
    except Exception:
        return []
    seen_ips = set()
    devices = []
    for _, r in ans:
        ip = r[ARP].psrc
        if ip in seen_ips:
            continue
        seen_ips.add(ip)
        mac = r[ARP].hwsrc
        devices.append({
            "ip": ip,
            "mac": mac,
            "vendor": None,
            "device_name": None,
            "open_ports": [],
            "packets_sent": 0,
            "packets_received": 0,
        })
    # Sort by IP for consistent display
    devices.sort(key=lambda x: [int(p) for p in x["ip"].split(".")])
    return devices


def arp_scan(cidr: str, timeout: float = SCAN_TIMEOUT) -> list[dict]:
    """
    Perform ARP scan on cidr (e.g. 192.168.1.0/24).
    Sends one ARP request per IP in the subnet. Returns list of devices with ip, mac.
    """
    if not SCAPY_AVAILABLE:
        return []
    try:
        net = IPNetwork(cidr)
        scan_cidr = str(net.network) + f"/{net.prefixlen}"
    except Exception:
        scan_cidr = cidr
    iface = get_default_interface()
    scapy_conf.verb = 0
    return _arp_scan_scapy(scan_cidr, timeout, iface)


def _ping_host(ip: str, timeout_sec: float = 1.5) -> bool:
    """Return True if host responds to ping."""
    try:
        if platform.system() == "Windows":
            cmd = ["ping", "-n", "1", "-w", str(int(timeout_sec * 1000)), ip]
        else:
            cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout_sec))), ip]
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout_sec + 1,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


def _get_arp_cache() -> dict[str, str]:
    """Return dict of ip -> mac from system ARP cache."""
    out: dict[str, str] = {}
    try:
        if platform.system() == "Darwin":
            # macOS: arp -a gives "hostname (1.2.3.4) at aa:bb:cc:dd:ee:ff"
            r = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=5)
            if r.returncode != 0:
                return out
            import re
            for line in r.stdout.splitlines():
                m = re.search(r"\(([0-9.]+)\)\s+at\s+([0-9a-fA-F:]+)", line)
                if m:
                    out[m.group(1)] = m.group(2)
        elif platform.system() == "Linux":
            with open("/proc/net/arp", "r") as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 4 and parts[2] != "0x0":
                        out[parts[0]] = parts[3]
    except Exception:
        pass
    return out


def ping_sweep(cidr: str, timeout_per_host: float = 1.2) -> list[dict]:
    """
    Discover live hosts by pinging each IP in the subnet (no root required).
    Fills MAC from system ARP cache when available.
    """
    import time
    try:
        net = IPNetwork(cidr)
        scan_cidr = str(net.network) + f"/{net.prefixlen}"
    except Exception:
        scan_cidr = cidr
    hosts = [str(ip) for ip in IPNetwork(scan_cidr).iter_hosts()]
    if not hosts:
        return []
    live_ips: list[str] = []
    with ThreadPoolExecutor(max_workers=min(50, len(hosts))) as ex:
        futures = {ex.submit(_ping_host, ip, timeout_per_host): ip for ip in hosts}
        for f in as_completed(futures):
            if f.result():
                live_ips.append(futures[f])
    # Small delay to allow ARP cache to populate
    time.sleep(0.5)
    arp_cache = _get_arp_cache()
    devices = []
    for ip in sorted(live_ips, key=lambda x: [int(p) for p in x.split(".")]):
        mac = arp_cache.get(ip, "—")
        devices.append({
            "ip": ip,
            "mac": mac,
            "vendor": None,
            "device_name": None,
            "open_ports": [],
            "packets_sent": 0,
            "packets_received": 0,
        })
    return devices


def resolve_vendor(mac: str) -> Optional[str]:
    """Resolve vendor from MAC OUI."""
    if not MAC_LOOKUP_AVAILABLE:
        return None
    try:
        return MacLookup().lookup(mac)
    except Exception:
        return None


def resolve_device_name(ip: str) -> Optional[str]:
    """Try reverse DNS for device name, with multiple fallback methods."""
    import re
    
    # Try standard reverse DNS first with shorter timeout
    try:
        socket.setdefaulttimeout(1)
        name, _, _ = socket.gethostbyaddr(ip)
        socket.setdefaulttimeout(None)
        if name and name != ip:
            # Clean up the name (remove domain suffix for local devices)
            if '.local' in name:
                return name
            return name.split('.')[0]
    except (socket.herror, socket.gaierror, OSError):
        socket.setdefaulttimeout(None)
        pass
    
    # Try nmap for NetBIOS/DNS name (if available)
    try:
        result = subprocess.run(
            ['nmap', '-sn', '-R', '--max-retries', '1', '--host-timeout', '2s', ip],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            # Parse nmap output for hostname
            match = re.search(r'Nmap scan report for\s+(\S+)\s*\(', result.stdout)
            if match:
                name = match.group(1)
                if name and name != ip:
                    return name
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    
    # Try arp -a for hostname (macOS format often includes name)
    try:
        result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=3)
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                # macOS format: hostname (1.2.3.4) at aa:bb:cc:dd:ee:ff
                if ip in line:
                    match = re.search(r'^(\S+)\s*\(', line)
                    if match:
                        name = match.group(1)
                        if name and name != '?' and not re.match(r'\d+\.\d+\.\d+\.\d+', name):
                            return name
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    
    return None


def check_port_open(ip: str, port: int, timeout: float = PORT_SCAN_TIMEOUT) -> bool:
    """Check if a single port is open on ip."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        s.close()
        return result == 0
    except Exception:
        return False


def port_scan(ip: str, ports: list[int] | None = None) -> list[int]:
    """Scan ports on ip; returns list of open port numbers."""
    ports = ports or PORT_SCAN_PORTS
    open_ports = []
    with ThreadPoolExecutor(max_workers=min(20, len(ports))) as ex:
        futures = {ex.submit(check_port_open, ip, p): p for p in ports}
        for f in as_completed(futures):
            if f.result():
                open_ports.append(futures[f])
    return sorted(open_ports)


def risk_from_open_ports(open_ports: list[int]) -> str:
    """Compute risk level from number of open ports."""
    n = len(open_ports)
    if n >= OPEN_PORTS_HIGH_THRESHOLD:
        return RISK_HIGH
    if n >= OPEN_PORTS_MEDIUM_THRESHOLD:
        return RISK_MEDIUM
    if n > 0:
        return RISK_MEDIUM
    return RISK_LOW


def simulate_packet_stats(ip: str) -> tuple[int, int]:
    """Return (sent, received) deterministic packet counts for display based on IP."""
    # Use IP address to generate consistent pseudo-random values
    # This ensures the same IP always shows the same stats within a session
    ip_parts = ip.split('.')
    if len(ip_parts) == 4:
        base = (int(ip_parts[2]) * 256 + int(ip_parts[3])) % 4900 + 100
    else:
        base = 1000
    sent = base + hash(ip) % 500
    received = base + hash(ip[::-1]) % 500
    return sent, received


def get_local_mac() -> Optional[str]:
    """Get MAC of the default interface (cross-platform)."""
    if SCAPY_AVAILABLE:
        try:
            from scapy.all import get_if_hwaddr
            iface = get_default_interface()
            if iface:
                return get_if_hwaddr(iface)
        except Exception:
            pass
    return None


def _fallback_local_device() -> Optional[dict]:
    """Return a single device entry for this machine when ARP finds nothing."""
    ip, _ = get_local_ip_and_cidr()
    if not ip:
        return None
    mac = get_local_mac() or "—"
    return {
        "ip": ip,
        "mac": mac,
        "vendor": resolve_vendor(mac) if mac != "—" else None,
        "device_name": None,
        "open_ports": [],
        "packets_sent": 0,
        "packets_received": 0,
    }


def _is_ip_in_network(ip: str, network_cidr: str) -> bool:
    """Return True if ip belongs to the given network CIDR."""
    try:
        return str(ip) in IPNetwork(network_cidr)
    except Exception:
        return False


def full_scan(
    cidr: str | None = None,
    do_port_scan: bool = True,
    do_vendor_lookup: bool = True,
    do_device_name: bool = True,
) -> list[dict]:
    """
    Run full scan: ARP discovery, optional vendor, device name, port scan.
    Enriches each device with vendor, device_name, open_ports, risk, packet stats.
    Only adds "this machine" as fallback when we're scanning our own network (our IP is in the target CIDR).
    """
    local_ip, local_network_cidr = get_local_ip_and_cidr()
    network_cidr = local_network_cidr
    if cidr:
        try:
            net = IPNetwork(cidr)
            network_cidr = str(net.network) + f"/{net.prefixlen}"
        except Exception:
            network_cidr = cidr
    if not network_cidr:
        fallback = _fallback_local_device()
        return [fallback] if fallback else []

    # Combine ARP scan and ping sweep results to maximize discovered hosts.
    # ARP is preferred when available (better MAC accuracy), with ping sweep
    # filling any gaps (works without raw sockets / root).
    arp_devices = arp_scan(network_cidr)
    ping_devices = ping_sweep(network_cidr)

    devices_by_ip: dict[str, dict] = {}
    for d in arp_devices:
        ip = d.get("ip")
        if not ip:
            continue
        devices_by_ip[ip] = d

    for d in ping_devices:
        ip = d.get("ip")
        if not ip:
            continue
        existing = devices_by_ip.get(ip)
        if existing:
            # Prefer a real MAC address if ARP or ping cache has a better value
            has_mac = existing.get("mac") and existing.get("mac") != "—"
            new_mac = d.get("mac")
            if not has_mac and new_mac and new_mac != "—":
                existing["mac"] = new_mac
        else:
            devices_by_ip[ip] = d

    devices = sorted(devices_by_ip.values(), key=lambda x: [int(p) for p in x["ip"].split(".")])

    # Only add this machine as last resort when we're on the scanned network
    if not devices and local_ip and _is_ip_in_network(local_ip, network_cidr):
        fallback = _fallback_local_device()
        if fallback:
            devices = [fallback]
    for d in devices:
        if do_vendor_lookup and d.get("mac") and d.get("mac") != "—":
            d["vendor"] = resolve_vendor(d["mac"])
        if do_device_name:
            d["device_name"] = resolve_device_name(d["ip"])
        if do_port_scan:
            d["open_ports"] = port_scan(d["ip"])
        d["risk"] = risk_from_open_ports(d.get("open_ports", []))
        d["packets_sent"], d["packets_received"] = simulate_packet_stats(d["ip"])
    return devices
