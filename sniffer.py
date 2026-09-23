import os
import sys
from scapy.all import sniff, IP

# Define the log file path
LOG_FILE = "captured_ip_traffic.txt"

def process_packet(packet):
    """Callback function to extract and save IP addresses from captured packets."""
    # Check if the packet has an IP layer (IPv4)
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        
        # Format the output log string
        log_entry = f"Source: {src_ip} -> Destination: {dst_ip} | Protocol: {proto}\n"
        
        # Print to console
        print(log_entry.strip())
        
        # Append traffic logs to a text file
        with open(LOG_FILE, "a") as f:
            f.write(log_entry)

def main():
    # Ensure the script is run with administrative privileges
    if os.name != 'nt' and os.getuid() != 0:
        print("Error: This script must be run as root/administrator.")
        sys.exit(1)
        
    print(f"[*] Starting IP Sniffer... Logging traffic to {LOG_FILE}")
    print("[*] Press Ctrl+C to stop.\n")
    
    try:
        # sniff() continuously intercepts packets. 
        # filter="ip" ensures we only process IPv4 packets at the driver level.
        # Adding count=20 limits the capture to 20 packets for demonstration purposes.
        sniff(filter="ip", prn=process_packet, store=False, count=20)
    except KeyboardInterrupt:
        print("\n[*] Sniffing stopped. Logs safely stored.")
        sys.exit(0)

if __name__ == "__main__":
    main()
