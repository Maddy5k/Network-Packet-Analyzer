import streamlit as st
from scapy.all import *
import threading
import time

# Function to process each packet
def packet_callback(packet, packet_list):
    packet_info = {}
    
    # Capture source and destination IP addresses
    if IP in packet:
        packet_info["Source IP"] = packet[IP].src
        packet_info["Destination IP"] = packet[IP].dst
    
    # Capture the transport layer protocol (TCP, UDP)
    if TCP in packet:
        packet_info["Protocol"] = "TCP"
        packet_info["Source Port"] = packet[TCP].sport
        packet_info["Destination Port"] = packet[TCP].dport
    elif UDP in packet:
        packet_info["Protocol"] = "UDP"
        packet_info["Source Port"] = packet[UDP].sport
        packet_info["Destination Port"] = packet[UDP].dport
    
    # Capture the payload (data) of the packet
    if Raw in packet:
        packet_info["Payload"] = packet[Raw].load.decode(errors='ignore')
    
    packet_list.append(packet_info)

# Streamlit function to display the packets in real-time
def display_packets(packet_list):
    st.title("Live Packet Sniffer")
    st.write("Capturing network packets...")

    # Create a real-time update display
    for packet_info in packet_list:
        st.write(packet_info)

# Threaded function to sniff packets
def sniff_packets(packet_list):
    sniff(prn=lambda packet: packet_callback(packet, packet_list), store=0, timeout=10)

# Streamlit app
def main():
    packet_list = []
    st.sidebar.header("Packet Sniffer Configuration")
    start_button = st.sidebar.button("Start Sniffing")

    if start_button:
        # Run packet sniffer in a separate thread to allow real-time updates in Streamlit
        thread = threading.Thread(target=sniff_packets, args=(packet_list,))
        thread.start()
        
        # Continuously update the packet display
        while thread.is_alive():
            display_packets(packet_list)
            time.sleep(1)

if __name__ == "__main__":
    main()
