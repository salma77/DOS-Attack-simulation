#! /usr/bin/env python3.9

from collections import Counter
from scapy.all import sniff

# Create a Packet Counter
packet_counts = Counter()

# Define the Custom Action function
def custom_action(packet):
    # Create tuple of Src/Dst in sorted order
    key = tuple(sorted([packet[0][1].src, packet[0][1].dst]))
    packet_counts.update([key])
    return f"Packet #{sum(packet_counts.values())}: {packet[0][1].src} ==> {packet[0][1].dst}"

# Setup sniff, filtering for IP traffic
# Note: prn takes a function and executes it per sniff
sniff(filter="ip", prn=custom_action, count=20)

# Define threshold of DOS attack
threshold = 6

# Print out packet count per A <--> Z address pair
# print("\n".join(f"{f'{key[0]} <--> {key[1]}'}: {count}" for key, count in packet_counts.items()))
for key, count in packet_counts.items():
    print(f"{f'{key[0]} <--> {key[1]}'}: {count}")
    if count >= threshold:
        print("DOS Attack")