#!/usr/bin/env python3
# Copyright (C) 2022 Carnegie Mellon University
# Copyright (C) 2025 University of Texas at Austin

from scapy.all import rdpcap, Raw, IP
import matplotlib.pyplot as plt

# Change this to be your pcap file
FILE_TO_READ = "capture.pcap"

packets = rdpcap(FILE_TO_READ)
packet_list = []
times = []
base = 0
server_port = 8000
num_packets = 0

# This script assumes that only the client is sending data to the server.
for packet in packets:
    payload = packet[Raw].load

    if IP not in packet:
        continue

    if int.from_bytes(payload[:4], byteorder="big") != 51085:
        continue

    # Count the number of data packets going into the network.
    if packet[IP].dport == server_port:
        hlen = int.from_bytes(payload[16:18], byteorder="big")
        plen = int.from_bytes(payload[18:20], byteorder="big")
        if plen > hlen:  # Data packet
            num_packets = num_packets + 1
        time = packet.time
        if base == 0:
            base = time
        packet_list.append(num_packets)
        times.append(time - base)

    # Count the number of ACKs from server to client.
    elif packet[IP].sport == server_port:
        mask = int.from_bytes(payload[20:21], byteorder="big")
        if (mask & 4) == 4:  # ACK PACKET
            num_packets = max(num_packets - 1, 0)
        time = packet.time
        if base == 0:
            base = time
        packet_list.append(num_packets)
        times.append(time - base)


if __name__ == "__main__":
    # https://matplotlib.org/users/pyplot_tutorial.html for how to format and
    # make a good quality graph.
    plt.figure(figsize=(24, 6))
    plt.scatter(times, packet_list)
    plt.xticks(fontsize=18)
    plt.yticks(fontsize=18)
    plt.xlabel("Time (s)", fontsize=18)
    plt.ylabel("Number of Packets", fontsize=18)
    plt.title("Number of Packets Over Time", fontsize=24)
    plt.savefig("graph.png", bbox_inches='tight')
