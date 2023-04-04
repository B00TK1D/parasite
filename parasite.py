#!/usr/bin/env python3

import logging
import sys

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
# Ready command line parameters
if len(sys.argv) < 3:
    print("Usage: python3 " + sys.argv[0] + " <pcap> <server-ip> <listen-interface> [secret-key]")
    sys.exit(1)

print("Initializing...")
from scapy.all import *

packet_types = {}

secret_key = b'scrt'
saved_offset = 0
saved_length = 0
server_ip = ''
listen_interface = ''

def calculate_hash(packet):
    # Calculate the hash of key parts of the packet's header
    # This is used to identify duplicate packet types
    # The hash is calculated using the following fields:
    #   - Protocol type
    #   - If the protocol is TCP or UDP, the destination port

    # Get the packet's protocol type
    protocol = packet[1].name
    port = 0
    # Get the packet's destination port
    try:
        protocol = packet[2].name
        if protocol == 'TCP':
            port = packet[2].dport
        elif protocol == 'UDP':
            port = packet[2].dport
    except:
        pass

    # Return a string of the protocol and port
    return str(protocol) + ":" + str(port)


def packet_list(pcap):
    # Load a pcap file and return a list of packets
    return rdpcap(pcap)


def filter_external(packets):
    # Filter out all packets that have a destination IP address that is a private IP address
    # This is used to remove packets that are not leaving the network
    filtered_packets = []
    for packet in packets:
        if IP in packet:
            if (not (packet[IP].dst.startswith('192.168') or 
                    packet[IP].dst.startswith('10.') or 
                    packet[IP].dst.startswith('172.16.') or 
                    packet[IP].dst.startswith('172.17.') or 
                    packet[IP].dst.startswith('172.18.') or 
                    packet[IP].dst.startswith('172.19.') or 
                    packet[IP].dst.startswith('172.20.') or 
                    packet[IP].dst.startswith('172.21.') or 
                    packet[IP].dst.startswith('172.22.') or 
                    packet[IP].dst.startswith('172.23.') or 
                    packet[IP].dst.startswith('172.24.') or 
                    packet[IP].dst.startswith('172.25.') or 
                    packet[IP].dst.startswith('172.26.') or 
                    packet[IP].dst.startswith('172.27.') or 
                    packet[IP].dst.startswith('172.28.') or 
                    packet[IP].dst.startswith('172.29.') or 
                    packet[IP].dst.startswith('172.30.') or 
                    packet[IP].dst.startswith('172.31.'))):
                filtered_packets.append(packet)
                # print(packet.summary())
    return filtered_packets


def packet_data(packet):
    if IP in packet:
        return bytes(packet[IP])[(packet[IP].ihl * 4):]
    return b""

def packet_header(packet):
    if IP in packet:
        return bytes(packet[IP])[:packet[IP].ihl * 4]
    return b""


def categorize_packets(packets):
    # Seperate a list of packets into a dictionary of lists of packets based on the packet type
    # This is used to group packets by their protocol and destination port
    packet_types = {}
    # Loop through each packet in the list
    for packet in packets:
        # Calculate the packet hash
        packet_hash = calculate_hash(packet)
        # Check if the packet is already in the dictionary
        if packet_hash not in packet_types:
            packet_types[packet_hash] = []
        # Add the packet to the dictionary
        packet_types[packet_hash].append(packet)
    # Return the dictionary of lists of packets
    return packet_types


def diff_tree(packets):
    # Build a list that contains the number of packets which have a difference for each byte in the packet
    # This is used to determine the offset of the payload

    # Calculate the maximum packet payload length
    max_length = max([len(packet_data(packet)) for packet in packets])

    # Create a list of zeros
    diff_list = [0] * max_length

    comparisons = [0] * max_length

    # Loop through each packet in the list with an index
    for i, p1 in enumerate(packets):
        # Loop through each packet in the list again, from 0 to the current index
        for j, p2 in enumerate(packets[i:]):
            # Get packet data
            p1_data = packet_data(p1)
            p2_data = packet_data(p2)
            # Skip if the packets are the same
            if i == j:
                continue
            # Swap the packets if the first packet is longer than the second
            if len(p1_data) > len(p2_data):
                p1_data, p2_data = p2_data, p1_data
            # Loop through each byte in the packet
            for k in range(len(p1_data)):
                # Check if the byte is different
                comparisons[k] += 1
                if p1_data[k] != p2_data[k]:
                    # Increment the counter for the byte
                    diff_list[k] += 1
    
    for i in range(len(diff_list)):
        if comparisons[i] > 0:
            diff_list[i] = diff_list[i] / comparisons[i]
    
    # Return the list of differences
    return diff_list



def find_payload(diff_list, threshold=0.80):
    # Find the offset and length of the longest sequence of bytes with a difference greater than the threshold
    # This is used to determine the offset and length of the payload
    longest = 0
    offset = 0

    best = 0

    current_length = 0
    # Loop through each byte in the list
    for i, diff in enumerate(diff_list):
        if diff < threshold:
            current_length = 0
            continue
        current_length += 1
        if current_length > longest:
            longest = current_length
            offset = i - longest + 1

    # Return the offset and length of the payload
    return offset, longest


def longest_packet(packet_list):
    # Find the longest packet in the dictionary of lists of packets
    # This is used to determine the best packet to use as a template
    longest = 0
    longest_packet = None
    # Loop through each packet in the list
    for packet in packet_list:
        # Check if the packet is longer than the longest packet
        if len(packet_data(packet)) > longest:
            # Update the longest packet
            longest = len(packet_data(packet))
            longest_packet = packet
    # Return the longest packet
    return longest_packet



def create_client(packet, callback, offset, length):
    global secret_key, server_ip
    # Generate a python script for a netcat-like client which embeds its payload in specified area of the provided packet
    
    template = """
#!/usr/bin/env python3
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import IP, send
s = bytearray(""" + str(bytes(packet[IP])) + """)
s[""" + str(offset) + ":" + str(offset + len(secret_key)) + """] = """ + str(secret_key) + """
while True:
    try:
        d = input().encode()
    except:
        break
    d += b'\\n'
    while True:
        if len(d) < """ + str(length - len(secret_key)) + """:
            s[""" + str(offset + len(secret_key)) + ":" + str(offset + length) + """] = d
            s[""" + str(offset + len(secret_key)) + """+len(d):""" + str(offset + length) + """] = b'\\x00' * (""" + str(length - len(secret_key)) + """ - len(d))
            p = IP(bytes(s))
            p[IP].dst = '""" + str(server_ip) + """'
            send(p, verbose=0)
            break
        else:
            s[""" + str(offset + len(secret_key)) + ":" + str(offset + length) + """] = d[:""" + str(length - len(secret_key)) + """]
            p = IP(bytes(s))
            p[IP].dst = '""" + str(server_ip) + """'
            send(p, verbose=0)
            d = d[""" + str(length - len(secret_key)) + """:]
"""

    return template


# Listen for packets
def packet_callback(packet):
    global saved_offset, saved_length, secret_key
    # Print the packet summary
    if packet.haslayer(IP):
        s = bytearray(bytes(packet[IP]))
        m = s[saved_offset:saved_offset + len(secret_key)]
        if m != secret_key:
            return
        d = s[saved_offset + len(secret_key):saved_offset + saved_length]
        print(d.decode('latin-1'), end='')


def server_listener():
    global listen_interface
    # Capture packets in promiscuous mode
    sniff(iface="lo0", prn=packet_callback, store=0, count=0)




def main():
    global saved_offset, saved_length, secret_key, server_ip
    pcap_path = sys.argv[1]
    server_ip = sys.argv[2]
    listen_interface = sys.argv[3]
    if len(sys.argv) > 4:
        secret_key = sys.argv[4].encode()
    # Open the pcap file
    print("Opening pcap file...")
    packets = packet_list(pcap_path)
    # Filter out packets that are not leaving the network
    print("Filtering for external packets...")
    packets = filter_external(packets)
    # Categorize the packets by their protocol and destination port
    print("Categorizing packets...")
    packet_types = categorize_packets(packets)
    # Loop through each packet type
    best_payload = 0, 0, None
    print("Building diff trees (this could take a while for large pcaps)...")
    for packet_type in packet_types:
        # Get the list of packets for the packet type
        packets = packet_types[packet_type]
        # Calculate the offset and length of the payload
        # print(packet_type)
        # print(len(packets))
        diffs = diff_tree(packets)
        # print(diffs)
        offset, length = find_payload(diffs)
        if length > best_payload[1]:
            best_payload = offset, length, packet_type

    best_payload_packet = longest_packet(packet_types[best_payload[2]])
    saved_offset = best_payload[0]
    saved_length = best_payload[1]
    print("Selected best packet for skeleton: " + best_payload_packet.summary())

    # Generate a python script for a netcat-like client which embeds its payload in specified area of the provided packet
    client = create_client(best_payload_packet, '127.0.0.1', best_payload[0], best_payload[1])
    #print(client)
    # Write template to out/client.py
    print("Writing client to client.py...")
    with open('client.py', 'w') as f:
        f.write(client)

    # Start the server listener
    print("Starting server listener, press Ctrl+C to exit...\n\n")
    server_listener()

if __name__ == '__main__':
    main()