from scapy.all import *
import matplotlib.pyplot as plt

packet_count = 0
packet_sizes = []

def packet_handler(packet):
    global packet_count, packet_sizes

    packet_count += 1
    packet_sizes.append(len(packet))

    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        payload = packet[TCP].payload
        timestamp = packet.time
        print(f"TCP Packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
        print(f"Payload: {payload}")
        print(f"Timestamp: {timestamp}")
        print("------------------------")
    elif packet.haslayer(UDP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        payload = packet[UDP].payload
        timestamp = packet.time
        print(f"UDP Packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
        print(f"Payload: {payload}")
        print(f"Timestamp: {timestamp}")
        print("------------------------")

def packet_statistics():
    print("Packet Statistics")
    print("------------------------")
    print(f"Total packets: {packet_count}")
    print(f"Average packet size: {sum(packet_sizes)/len(packet_sizes):.2f} bytes")
    print("------------------------")
    plt.hist(packet_sizes, bins=50)
    plt.xlabel("Packet Size (bytes)")
    plt.ylabel("Count")
    plt.title("Packet Size Distribution")
    plt.show()

# Start sniffing packets on the network interface
sniff(prn=packet_handler, filter="tcp or udp", store=0)
packet_statistics()
