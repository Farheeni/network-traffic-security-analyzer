import os
import platform
import subprocess
import logging
import threading
import time
import queue
import streamlit as st
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR
from scapy.all import sniff

# Set up logging
LOG_FILE = 'network_traffic_log.txt'
if os.path.exists(LOG_FILE):
    os.remove(LOG_FILE)

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Queues for packet and alert information
packet_queue = queue.Queue()
alert_queue = queue.Queue()

# Dictionary to track packet counts for IPs
traffic_count = {}

# Log each packet's details to the log file and queue
def log_packet_info(packet):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    src_ip = packet[IP].src if packet.haslayer(IP) else "N/A"
    dest_ip = packet[IP].dst if packet.haslayer(IP) else "N/A"
    packet_size = len(packet)
    
    packet_info = (
        f"[{timestamp}] Packet Info:\n"
        f"Source IP: {src_ip}, Destination IP: {dest_ip}, Size: {packet_size} bytes\n"
    )
    # Log to file and queue
    with open(LOG_FILE, 'a') as log_file:
        log_file.write(packet_info + "\n")
    packet_queue.put(packet_info)

# Check for suspicious activities
def contains_edu_domain(packet):
    if packet.haslayer(DNS) and packet[DNS].qr == 0:
        dns_query = packet[DNSQR].qname.decode()
        return ".edu" in dns_query
    return False

def is_port_scan(packet):
    if packet.haslayer(TCP) and packet[TCP].flags == "S":
        src_ip = packet[IP].src
        dest_port = packet[TCP].dport
        if src_ip not in traffic_count:
            traffic_count[src_ip] = {'ports': set(), 'dns_count': 0}
        traffic_count[src_ip]['ports'].add(dest_port)
        if len(traffic_count[src_ip]['ports']) > 10:
            return True, src_ip
    return False, None

def is_dns_tunneling(packet):
    if packet.haslayer(DNSQR):
        src_ip = packet[IP].src
        if src_ip not in traffic_count:
            traffic_count[src_ip] = {'ports': set(), 'dns_count': 0}
        traffic_count[src_ip]['dns_count'] += 1
        if traffic_count[src_ip]['dns_count'] > 50:
            return True, src_ip
    return False, None

def log_alert(alert_message):
    # Write alert to the log file
    with open(LOG_FILE, 'a') as log_file:
        log_file.write(alert_message + "\n")
    # Queue the alert for display in Streamlit
    alert_queue.put(alert_message)

def packet_handler(packet):
    if IP in packet:
        # Log packet information
        log_packet_info(packet)
        src_ip = packet[IP].src
        dest_ip = packet[IP].dst

        # Detect suspicious activity
        if contains_edu_domain(packet):
            alert_message = f"Suspicious .edu domain access detected from {src_ip} to {dest_ip}."
            log_alert(alert_message)

        port_scan, scan_ip = is_port_scan(packet)
        if port_scan:
            alert_message = f"Port scanning detected from {scan_ip}."
            log_alert(alert_message)

        dns_tunnel, tunnel_ip = is_dns_tunneling(packet)
        if dns_tunnel:
            alert_message = f"Potential DNS tunneling detected from {tunnel_ip}."
            log_alert(alert_message)

def sniff_packets(interface):
    try:
        sniff(iface=interface, prn=packet_handler, store=0)
    except Exception as e:
        logging.error(f"Error sniffing packets: {e}")

# Streamlit Interface
st.title("Network Packet Sniffer with Detailed Packet Logs and Suspicious Alerts")
interface = st.text_input("Enter network interface (e.g., eth0, wlan0):")
start_sniffing = st.button("Start Sniffing")
stop_sniffing = st.button("Stop Sniffing")

# Start packet sniffing in a background thread
if start_sniffing and interface:
    if "sniffing_thread" not in st.session_state:
        st.session_state.sniffing_thread = threading.Thread(target=sniff_packets, args=(interface,), daemon=True)
        st.session_state.sniffing_thread.start()
        st.success("Sniffing started...")

# Stop sniffing
if stop_sniffing:
    if "sniffing_thread" in st.session_state:
        st.warning("Stopping packet sniffing...")
        del st.session_state.sniffing_thread
        with open(LOG_FILE, 'a') as log_file:
            log_file.write("\n--- End of Session Report ---\n")
        st.success("Sniffing stopped and log saved.")

# Display alerts and packet info
alerts_placeholder = st.empty()
packet_info_placeholder = st.empty()

# Main display loop
while True:
    time.sleep(1)  # Poll every second
    alert_messages = []
    packet_messages = []
    
    # Retrieve alerts
    while not alert_queue.empty():
        alert_messages.append(alert_queue.get())
    # Display alerts as popups
    if alert_messages:
        with alerts_placeholder.container():
            for alert in alert_messages:
                # This will appear as a popup alert in the app
                st.warning(alert)
                time.sleep(5)  # Show alert for 5 seconds (adjustable)
                alerts_placeholder.empty()  # Clear the alert after displaying it
                
    # Retrieve packets
    while not packet_queue.empty():
        packet_messages.append(packet_queue.get())
    # Display packet info
    if packet_messages:
        with packet_info_placeholder.container():
            st.text("\n".join(packet_messages))
