from collections import defaultdict
import time

flows = defaultdict(lambda: {
    "start_time": None,
    "packet_count": 0,
    "byte_count": 0
})

def update_flow(packet):
    """
    Update flow statistics from captured packets.
    """

    if not packet.haslayer("IP"):
        return None

    ip = packet["IP"]

    flow_id = (
        ip.src,
        ip.dst,
        ip.proto
    )

    flow = flows[flow_id]

    if flow["start_time"] is None:
        flow["start_time"] = time.time()

    flow["packet_count"] += 1
    flow["byte_count"] += len(packet)

    duration = time.time() - flow["start_time"]

    return {
        "src_ip": ip.src,
        "dst_ip": ip.dst,
        "protocol": ip.proto,
        "duration": round(duration, 3),
        "packet_count": flow["packet_count"],
        "byte_count": flow["byte_count"]
    }