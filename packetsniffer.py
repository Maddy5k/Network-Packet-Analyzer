from scapy.all import *
import datetime

# Function to process each packet
def packet_callback(packet):
    print(f"\nPacket captured at {datetime.datetime.now()}")
    print(f"Packet summary: {packet.summary()}")

    # Capture source and destination IP addresses
    if IP in packet:
        print(f"Source IP: {packet[IP].src}")
        print(f"Destination IP: {packet[IP].dst}")

    # Capture the transport layer protocol (TCP, UDP)
    if TCP in packet:
        print(f"Protocol: TCP")
        print(f"Source Port: {packet[TCP].sport}")
        print(f"Destination Port: {packet[TCP].dport}")
    
    elif UDP in packet:
        print(f"Protocol: UDP")
        print(f"Source Port: {packet[UDP].sport}")
        print(f"Destination Port: {packet[UDP].dport}")
    
    # Capture the payload (data) of the packet
    if Raw in packet:
        print(f"Payload Data (Raw): {packet[Raw].load}")

# Start sniffing on the network interface
def start_sniffing(interface="eth0"):
    print(f"Starting packet sniffing on {interface}...\n")
    sniff(iface=interface, prn=packet_callback, store=0)

if __name__ == "__main__":
    # Set the network interface to sniff on (e.g., "eth0" or "wlan0" for wireless)
    start_sniffing("eth0")  # Use the correct interface name for your system
