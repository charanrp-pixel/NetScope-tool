"""Configuration for NetScope."""
import os

# Flask
SECRET_KEY = os.environ.get("SECRET_KEY", "netscope-dev-secret-change-in-production")
DEBUG = os.environ.get("FLASK_DEBUG", "1").lower() in ("1", "true", "yes")

# Scanning
SCAN_TIMEOUT = 10  # wait for ARP replies (longer for large subnets)
PORT_SCAN_PORTS = [21, 22, 23, 80, 443, 445, 3389, 8080]
PORT_SCAN_TIMEOUT = 0.5

# Risk scoring
RISK_LOW = "low"
RISK_MEDIUM = "medium"
RISK_HIGH = "high"
OPEN_PORTS_MEDIUM_THRESHOLD = 2
OPEN_PORTS_HIGH_THRESHOLD = 5
