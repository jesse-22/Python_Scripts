import os
import sys
from collections import Counter
from scapy.all import sniff, IP

# Define the summary log file path
SUMMARY_FILE = "top_traffic_report.txt"

# Counter to keep track of packet hits per IP address
ip_tracker = Counter()

def process_packet(packet):
    """Tracks packet counts per IP and logs the highest traffic generator."""
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # Increment counts for both the sender and receiver
        ip_tracker[src_ip] += 1
        ip_tracker[dst_ip] += 1
        
        # Determine which IP address currently has the most traffic
        most_common_ip, total_packets = ip_tracker.most_common(1)[0]
        
        # Clear terminal screen dynamically for a clean, real-time dashboard view
        os.system('cls' if os.name == 'nt' else 'clear')
        
        print("=" * 50)
        print("          REAL-TIME TRAFFIC MONITOR          ")
        print("=" * 50)
        print(f"Active unique IPs tracked: {len(ip_tracker)}")
        print("-" * 50)
        print(f"🔥 TOP TRAFFIC GENERATOR:")
        print(f"   IP Address:  {most_common_ip}")
        print(f"   Packet Count: {total_packets}")
        print("=" * 50)
        print("[*] Press Ctrl+C to stop and save the final report.")
        
        # Write/Overwrite the running status file with the top culprit
        with open(SUMMARY_FILE, "w") as f:
            f.write("=" * 50 + "\n")
            f.write("         HIGHEST NETWORK TRAFFIC REPORT         \n")
            f.write("=" * 50 + "\n")
            f.write(f"Top IP Address:       {most_common_ip}\n")
            f.write(f"Total Packets Logged: {total_packets}\n")
            f.write("-" * 50 + "\n")
            f.write("Top 5 Most Active IPs:\n")
            for ip, count in ip_tracker.most_common(5):
                f.write(f" - {ip}: {count} packets\n")
            f.write("=" * 50 + "\n")

def main():
    # Ensure administrative elevation
    if os.name != 'nt' and os.getuid() != 0:
        print("Error: This script must be run as root/administrator.")
        sys.exit(1)
        
    print("[*] Initializing packet sniffer...")
    
    try:
        # Intercept IPv4 packets continuously
        sniff(filter="ip", prn=process_packet, store=False)
    except KeyboardInterrupt:
        print(f"\n[*] Sniffing stopped. Final traffic summary saved to {SUMMARY_FILE}")
        sys.exit(0)

if __name__ == "__main__":
    main()
