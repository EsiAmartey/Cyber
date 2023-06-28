from scapy.all import *

def packet_handler(packet):
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        print(f"TCP Packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
    elif packet.haslayer(UDP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        print(f"UDP Packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

# Start sniffing packets on the network interface
sniff(prn=packet_handler, filter="tcp or udp", store=0)
