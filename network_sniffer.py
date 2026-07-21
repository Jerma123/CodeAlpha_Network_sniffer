from scapy.all import IP, IPv6, TCP, UDP, Ether, Raw, sniff, wrpcap

captured_packets = []


def packet_callback(packet):
    captured_packets.append(packet)

    print("=" * 60)

    if packet.haslayer(Ether):
        print(f"Source MAC        : {packet[Ether].src}")
        print(f"Destination MAC   : {packet[Ether].dst}")

    if packet.haslayer(IP):
        print(f"Source IP         : {packet[IP].src}")
        print(f"Destination IP    : {packet[IP].dst}")
        proto = packet[IP].proto
        proto_name = "TCP" if proto == 6 else "UDP" if proto == 17 else "ICMP" if proto == 1 else "Other"
        print(f"Protocol          : {proto_name} ({proto})")
    elif packet.haslayer(IPv6):
        print(f"Source IP         : {packet[IPv6].src}")
        print(f"Destination IP    : {packet[IPv6].dst}")
        nh = packet[IPv6].nh
        proto_name = "TCP" if nh == 6 else "UDP" if nh == 17 else "ICMPv6" if nh == 58 else "Other"
        print(f"Protocol          : {proto_name} ({nh})")

    if packet.haslayer(TCP):
        print(f"Source Port       : {packet[TCP].sport}")
        print(f"Destination Port  : {packet[TCP].dport}")
    elif packet.haslayer(UDP):
        print(f"Source Port       : {packet[UDP].sport}")
        print(f"Destination Port  : {packet[UDP].dport}")

    print(f"Packet Length     : {len(packet)} bytes")

    if packet.haslayer(Raw):
        payload = packet[Raw].load[:100]
        print(f"Payload (Data)    : {payload}")
    else:
        print(f"Payload (Data)    : No raw payload data")


print("Network Sniffer is running...")
print("Press Ctrl + C to stop.")

try:
    sniff(prn=packet_callback, store=False)
except KeyboardInterrupt:
    print("\nStopping capture...")

if captured_packets:
    wrpcap("captured_packets.pcap", captured_packets)
    print(f"Saved {len(captured_packets)} packets to captured_packets.pcap")
else:
    print("No packets were captured.")