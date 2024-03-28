from scapy.all import *

def packet_handler(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        print(f'Source IP: {src_ip} --> Desination IP: {dst_ip}')

sniff(filter="ip", prn = packet_handler, count = 10)
