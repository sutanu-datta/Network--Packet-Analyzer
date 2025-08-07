from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime

def process_packet(packet):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto
        payload = bytes(packet[IP].payload)[:20]  # Show a preview of the payload

        # Determine protocol
        if packet.haslayer(TCP):
            protocol = "TCP"
        elif packet.haslayer(UDP):
            protocol = "UDP"
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
        else:
            protocol = f"Other({proto})"

        print(f"[{timestamp}] {ip_src} -> {ip_dst} | Protocol: {protocol} | Payload: {payload}")

def main():
    print("Starting packet capture... Press Ctrl+C to stop.\n")
    
    try:
        sniff(filter="ip", prn=process_packet, store=False)
    except PermissionError:
        print("❌ Permission denied. Please run the script as administrator/root.")
    except KeyboardInterrupt:
        print("\n🛑 Packet capture stopped by user.")

if __name__ == "__main__":
    main()
