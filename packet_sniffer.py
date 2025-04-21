from scapy.all import IP, TCP, UDP, send
import json
from nids import log_intrusion

# Load signatures from JSON file
with open("signatures.json") as f:
    signatures = json.load(f)

suspicious_ips = set(signatures.get("suspicious_ips", []))
suspicious_ports = set(signatures.get("suspicious_ports", []))

def check_packet(packet):
    """Function to check if the packet is suspicious"""
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet.sport if hasattr(packet, 'sport') else None
        dst_port = packet.dport if hasattr(packet, 'dport') else None

        alert = None

        # Check against suspicious IPs
        if src_ip in suspicious_ips or dst_ip in suspicious_ips:
            alert = "Suspicious IP Detected"

        # Check against suspicious ports
        elif src_port in suspicious_ports or dst_port in suspicious_ports:
            alert = "Suspicious Port Accessed"

        if alert:
            log_intrusion(alert, src_ip, dst_ip, src_port, dst_port)

def simulate_traffic():
    """Function to simulate traffic and detect suspicious activity"""
    print("Simulating packets...")

    # Simulate suspicious traffic (e.g., suspicious IP and port)
    suspicious_packet_1 = IP(src="192.168.1.100", dst="192.168.1.1") / TCP(sport=1234, dport=80)
    suspicious_packet_2 = IP(src="10.0.0.200", dst="192.168.1.1") / UDP(sport=12345, dport=8080)

    # Simulate non-suspicious traffic
    non_suspicious_packet_1 = IP(src="192.168.1.102", dst="192.168.1.1") / TCP(sport=1000, dport=443)
    non_suspicious_packet_2 = IP(src="192.168.1.103", dst="192.168.1.1") / UDP(sport=9999, dport=80)

    # Check all simulated packets
    check_packet(suspicious_packet_1)
    check_packet(suspicious_packet_2)
    check_packet(non_suspicious_packet_1)
    check_packet(non_suspicious_packet_2)

# Call the function to simulate traffic
simulate_traffic()
