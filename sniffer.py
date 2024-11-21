import os
import time
import logging
import threading
import queue
import re
import streamlit as st
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR
from scapy.all import sniff
import warnings

warnings.filterwarnings("ignore", message="missing ScriptRunContext")

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

# Suspicious domains
SUSPICIOUS_DOMAINS = ['.edu', '.uk', '.pp', 'faceb00k']
MAX_DNS_TRAFFIC_THRESHOLD = 10000 # Threshold for DNS traffic alerts

# Dictionary to track DNS query counts
dns_query_count = {}

# Log each packet's details to the log file and queue
def log_packet_info(packet):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    src_ip = packet[IP].src if packet.haslayer(IP) else "N/A"
    dest_ip = packet[IP].dst if packet.haslayer(IP) else "N/A"
    packet_size = len(packet)
    protocol = packet.summary()

    packet_info = (
        f"[{timestamp}] Packet Info:\n"
        f"Source IP: {src_ip}, Destination IP: {dest_ip}, Protocol: {protocol}, Size: {packet_size} bytes\n"
    )
    with open(LOG_FILE, 'a') as log_file:
        log_file.write(packet_info + "\n")
    packet_queue.put(packet_info)

# Check for suspicious domains
def contains_suspicious_domain(packet):
    if packet.haslayer(DNS) and packet[DNS].qr == 0:  # DNS query
        dns_query = packet[DNSQR].qname.decode()  # Get queried domain name
        for domain in SUSPICIOUS_DOMAINS:
            if domain in dns_query.lower():
                return True, dns_query
    return False, None

# Log and display alerts
def log_alert(alert_message):
    with open(LOG_FILE, 'a') as log_file:
        log_file.write(alert_message + "\n")
    alert_queue.put(alert_message)

# Check DNS traffic
def check_dns_traffic(packet):
    if packet.haslayer(DNSQR):
        dns_query = packet[DNSQR].qname.decode()
        src_ip = packet[IP].src
        if src_ip not in dns_query_count:
            dns_query_count[src_ip] = 0
        dns_query_count[src_ip] += 1

        # If DNS traffic exceeds the threshold, show an alert
        if dns_query_count[src_ip] > MAX_DNS_TRAFFIC_THRESHOLD:
            alert_message = f"⚠️ DNS Traffic Alert: {src_ip} has made more than {MAX_DNS_TRAFFIC_THRESHOLD} DNS queries."
            log_alert(alert_message)
            st.warning(alert_message)
            # Show bad message on the browser tab
            st.markdown(
                f"<script>document.title = '⚠️ High DNS Traffic Detected';</script>", 
                unsafe_allow_html=True
            )

def packet_handler(packet):
    if IP in packet:
        log_packet_info(packet)
        src_ip = packet[IP].src
        dest_ip = packet[IP].dst

        # Detect suspicious domains
        suspicious_domain, domain_name = contains_suspicious_domain(packet)
        if suspicious_domain:
            alert_message = f"⚠️ Suspicious domain access detected: {domain_name} from {src_ip} to {dest_ip}."
            log_alert(alert_message)
            st.warning(alert_message)  # Show as warning pop-up in Streamlit
            # Change browser tab title to show bad message continuously
            st.markdown(
                f"<script>document.title = '⚠️ Bad Website Detected: {domain_name}';</script>", 
                unsafe_allow_html=True
            )

        # Check DNS traffic
        check_dns_traffic(packet)

# Simulate DNS queries for demonstration
def simulate_dns_queries():
    simulated_queries = [
        "example.edu",
        "university.uk",
        "malicious.pp",
        "faceb00k.com",
    ]
    for query in simulated_queries:
        time.sleep(1)  # Delay between simulated queries
        alert_message = f"⚠️ Simulated suspicious domain detected: {query}."
        log_alert(alert_message)
        st.error(alert_message)

# Sniff packets and process them
def sniff_packets(interface):
    try:
        sniff(iface=interface, prn=packet_handler, store=0)
    except Exception as e:
        logging.error(f"Error sniffing packets: {e}")

# Streamlit Interface
st.title("Network Packet Sniffer with Suspicious Alerts and DNS Traffic Monitor")
interface = st.text_input("Enter network interface (e.g., eth0, wlan0):")
start_sniffing = st.button("Start Sniffing")
simulate_dns = st.button("Simulate DNS Queries")
stop_sniffing = st.button("Stop Sniffing")

# Start packet sniffing in a background thread
if start_sniffing and interface:
    if "sniffing_thread" not in st.session_state:
        st.session_state.sniffing_thread = threading.Thread(target=sniff_packets, args=(interface,), daemon=True)
        st.session_state.sniffing_thread.start()
        st.success("Sniffing started...")

# Simulate DNS queries
if simulate_dns:
    simulate_dns_queries()

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
    if alert_messages:
        with alerts_placeholder.container():
            for alert in alert_messages:
                st.error(alert)
                time.sleep(2)
                alerts_placeholder.empty()
                
    # Retrieve packets
    while not packet_queue.empty():
        packet_messages.append(packet_queue.get())
    if packet_messages:
        with packet_info_placeholder.container():
            st.text("\n".join(packet_messages))
