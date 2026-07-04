from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from datetime import datetime

packet_count = 0


def packet_callback(packet):
    global packet_count

    if packet.haslayer(IP):
        packet_count += 1

        print("\n" + "=" * 60)
        print(f"Packet Number : {packet_count}")
        print(f"Time          : {datetime.now().strftime('%H:%M:%S')}")
        print(f"Source IP     : {packet[IP].src}")
        print(f"Destination IP: {packet[IP].dst}")

        if packet.haslayer(TCP):
            protocol = "TCP"
        elif packet.haslayer(UDP):
            protocol = "UDP"
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
        else:
            protocol = "Other"

        print(f"Protocol      : {protocol}")
        print(f"Packet Length : {len(packet)} bytes")
        print("=" * 60)


print("=" * 60)
print("      NETWORK PACKET ANALYZER USING SCAPY")
print("=" * 60)
print("Capturing packets...")
print("Press CTRL + C to stop.\n")

sniff(prn=packet_callback, store=False)