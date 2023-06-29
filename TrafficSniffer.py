from scapy.all import *
import matplotlib.pyplot as plt
import threading

packet_count = 0
packet_sizes = []
flows = {}

def packet_handler(packet):
    global packet_count, packet_sizes, flows

    packet_count += 1
    packet_sizes.append(len(packet))

    if packet.haslayer(TCP):
        handle_tcp_packet(packet)
    elif packet.haslayer(UDP):
        handle_udp_packet(packet)
    elif packet.haslayer(ICMP):
        handle_icmp_packet(packet)
    elif packet.haslayer(DNS):
        handle_dns_packet(packet)

def handle_tcp_packet(packet):
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    src_port = packet[TCP].sport
    dst_port = packet[TCP].dport
    payload = packet[TCP].payload
    timestamp = packet.time

    # Process TCP packet and extract relevant information
    print(f"TCP Packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
    print(f"Payload: {payload}")
    print(f"Timestamp: {timestamp}")
    print("------------------------")

    # Perform flow analysis
    flow_key = (src_ip, dst_ip, src_port, dst_port)
    if flow_key in flows:
        flows[flow_key]['packet_count'] += 1
        flows[flow_key]['bytes'] += len(packet)
        flows[flow_key]['end_time'] = timestamp
    else:
        flows[flow_key] = {
            'start_time': timestamp,
            'end_time': timestamp,
            'packet_count': 1,
            'bytes': len(packet)
        }

def handle_udp_packet(packet):
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    src_port = packet[UDP].sport
    dst_port = packet[UDP].dport
    payload = packet[UDP].payload
    timestamp = packet.time

    # Process UDP packet and extract relevant information
    print(f"UDP Packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
    print(f"Payload: {payload}")
    print(f"Timestamp: {timestamp}")
    print("------------------------")

def handle_icmp_packet(packet):
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    icmp_type = packet[ICMP].type
    icmp_code = packet[ICMP].code
    timestamp = packet.time

    # Process ICMP packet and extract relevant information
    print(f"ICMP Packet: {src_ip} -> {dst_ip}")
    print(f"Type: {icmp_type}, Code: {icmp_code}")
    print(f"Timestamp: {timestamp}")
    print("------------------------")

def handle_dns_packet(packet):
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    timestamp = packet.time
    dns_query = packet[DNSQR].qname

    # Process DNS packet and extract relevant information
    print(f"DNS Packet: {src_ip} -> {dst_ip}")
    print(f"Timestamp: {timestamp}")
    print(f"Query: {dns_query}")
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

def flow_analysis():
    print("Flow Analysis")
    print("------------------------")
    for flow_key, flow_data in flows.items():
        src_ip, dst_ip, src_port, dst_port = flow_key
        packet_count = flow_data['packet_count']
        bytes_transferred = flow_data['bytes']
        flow_duration = flow_data['end_time'] - flow_data['start_time']

        print(f"Flow: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
        print(f"Packets: {packet_count}")
        print(f"Bytes Transferred: {bytes_transferred}")
        print(f"Flow Duration: {flow_duration:.2f} seconds")
        print("------------------------")

# Start sniffing packets on the network interfaces
interfaces = ["eth0", "eth1"]  # Update with your network interfaces
threads = []

for interface in interfaces:
    thread = threading.Thread(target=sniff, kwargs={"prn": packet_handler, "iface": interface, "store": 0})
    thread.start()
    threads.append(thread)

# Wait for all threads to complete
for thread in threads:
    thread.join()

packet_statistics()
flow_analysis()
