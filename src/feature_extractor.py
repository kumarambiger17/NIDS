from scapy.layers.inet import IP, TCP, UDP

def extract_features(packet):
    """
    Extract basic features from a packet.
    Later we'll expand this to more CICIDS-like flow features.
    """

    features = {}

    if packet.haslayer(IP):
        features["packet_length"] = len(packet)
        features["ttl"] = packet[IP].ttl
        features["protocol"] = packet[IP].proto
    else:
        return None

    if packet.haslayer(TCP):
        features["src_port"] = packet[TCP].sport
        features["dst_port"] = packet[TCP].dport
        features["tcp_flags"] = int(packet[TCP].flags)

    elif packet.haslayer(UDP):
        features["src_port"] = packet[UDP].sport
        features["dst_port"] = packet[UDP].dport
        features["tcp_flags"] = 0

    else:
        features["src_port"] = 0
        features["dst_port"] = 0
        features["tcp_flags"] = 0

    return features