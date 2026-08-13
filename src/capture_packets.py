from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

packet_count = 0

def process_packet(packet):
    global packet_count

    if packet.haslayer(IP):
        packet_count += 1

        src = packet[IP].src
        dst = packet[IP].dst
        protocol = "OTHER"

        if packet.haslayer(TCP):
            protocol = "TCP"

        elif packet.haslayer(UDP):
            protocol = "UDP"

        print("=" * 60)
        print(f"Packet No : {packet_count}")
        print(f"Source IP : {src}")
        print(f"Destination IP : {dst}")
        print(f"Protocol : {protocol}")
        print(f"Packet Length : {len(packet)} bytes")

print("Starting Packet Capture...")
print("Press CTRL + C to Stop\n")

sniff(prn=process_packet, store=False)