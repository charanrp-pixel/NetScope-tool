import threading
import time
from scapy.all import sniff, IP, TCP, UDP, ARP, ICMP, Ether
from collections import defaultdict
import json

# Global variables for traffic monitoring
_traffic_data = {}
_monitoring_threads = {}
_stop_events = {}

def packet_callback(packet, target_ip):
    """Process captured packets and update traffic statistics."""
    if not IP in packet:
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    packet_size = len(packet)

    # Initialize data structure if needed
    if target_ip not in _traffic_data:
        _traffic_data[target_ip] = {
            'total_packets': 0,
            'total_bytes': 0,
            'protocols': defaultdict(int),
            'connections': [],
            'recent_packets': [],
            'start_time': time.time()
        }

    data = _traffic_data[target_ip]

    # Update statistics
    data['total_packets'] += 1
    data['total_bytes'] += packet_size

    # Track protocols
    if TCP in packet:
        data['protocols']['TCP'] += 1
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif UDP in packet:
        data['protocols']['UDP'] += 1
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
    elif ICMP in packet:
        data['protocols']['ICMP'] += 1
        src_port = dst_port = None
    else:
        data['protocols']['Other'] += 1
        src_port = dst_port = None

    # Track connections
    if src_port and dst_port:
        connection = {
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': 'TCP' if TCP in packet else 'UDP',
            'size': packet_size,
            'timestamp': time.time()
        }
        data['connections'].append(connection)

        # Keep only recent connections (last 100)
        if len(data['connections']) > 100:
            data['connections'] = data['connections'][-100:]

    # Track recent packets
    packet_info = {
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'protocol': 'TCP' if TCP in packet else ('UDP' if UDP in packet else ('ICMP' if ICMP in packet else 'Other')),
        'size': packet_size,
        'timestamp': time.time(),
        'src_port': src_port,
        'dst_port': dst_port
    }
    data['recent_packets'].append(packet_info)

    # Keep only recent packets (last 50)
    if len(data['recent_packets']) > 50:
        data['recent_packets'] = data['recent_packets'][-50:]

def start_traffic_monitor(target_ip, interface=None):
    """Start monitoring network traffic for a specific IP."""
    if target_ip in _monitoring_threads:
        return True, "Already monitoring this IP."

    # Test permissions
    try:
        from scapy.all import conf
        test_packet = Ether()/IP(src="127.0.0.1", dst="127.0.0.1")/ICMP()
        # Just test if we can create packets, don't send
    except Exception as e:
        if "Permission" in str(e) or "not permitted" in str(e).lower():
            return False, "Traffic monitoring requires Administrator privileges. Please run the Application from the terminal using: sudo open /Users/jraghu/Downloads/Netscope/dist/Netscope.app"
        return False, f"Failed to initialize packet capture: {str(e)}"

    stop_event = threading.Event()
    _stop_events[target_ip] = stop_event

    def monitor_thread():
        try:
            # Create filter for the target IP
            filter_str = f"host {target_ip}"

            # Start sniffing
            sniff(
                filter=filter_str,
                prn=lambda pkt: packet_callback(pkt, target_ip),
                stop_filter=lambda pkt: stop_event.is_set(),
                store=0,
                timeout=300  # 5 minutes max per session
            )
        except Exception as e:
            print(f"Monitoring error for {target_ip}: {e}")

    thread = threading.Thread(target=monitor_thread, daemon=True)
    thread.start()

    _monitoring_threads[target_ip] = thread

    return True, f"Started monitoring traffic for {target_ip}."

def stop_traffic_monitor(target_ip):
    """Stop monitoring network traffic for a specific IP."""
    if target_ip in _stop_events:
        _stop_events[target_ip].set()
        if target_ip in _monitoring_threads:
            _monitoring_threads[target_ip].join(timeout=2.0)
            del _monitoring_threads[target_ip]
        del _stop_events[target_ip]
        return True, f"Stopped monitoring {target_ip}."
    return False, "IP is not currently being monitored."

def get_traffic_data(target_ip):
    """Get current traffic statistics for a monitored IP."""
    if target_ip not in _traffic_data:
        return None

    data = _traffic_data[target_ip].copy()

    # Calculate rates
    elapsed = time.time() - data['start_time']
    if elapsed > 0:
        data['packets_per_second'] = data['total_packets'] / elapsed
        data['bytes_per_second'] = data['total_bytes'] / elapsed
    else:
        data['packets_per_second'] = 0
        data['bytes_per_second'] = 0

    # Convert defaultdict to regular dict for JSON serialization
    data['protocols'] = dict(data['protocols'])

    return data

def get_monitored_ips():
    """Return list of IPs currently being monitored."""
    return list(_monitoring_threads.keys())

def clear_traffic_data(target_ip):
    """Clear traffic data for a specific IP."""
    if target_ip in _traffic_data:
        del _traffic_data[target_ip]
        return True, f"Cleared traffic data for {target_ip}."
    return False, "No traffic data found for this IP."