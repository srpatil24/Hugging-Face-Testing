import os
from scapy.all import *
import json

def packet_to_dict(packet):
    # Convert the packet to a dictionary representation
    packet_dict = {
        'id': packet.time,  # Use timestamp as the ID
        'text': f"{packet[IP].src}:{packet[TCP].sport} -> {packet[IP].dst}:{packet[TCP].dport}",
        'label': packet[TCP].flags,
        'metadata': {
            'timestamp': packet.time,
            'source': packet[IP].src,
            'destination': packet[IP].dst,
            'sport': packet[TCP].sport,
            'dport': packet[TCP].dport,
            'protocol': packet[IP].proto
        }
    }
    return packet_dict

def save_tcp_streams_from_pcap(input_file):
    # Read the pcap file
    packets = rdpcap(input_file)
    # Group packets by stream
    streams = defaultdict(list)
    for packet in packets:
        if packet.haslayer(TCP) and packet.haslayer(IP):
            # Create a unique key for the stream (based on src/dest IP and src/dest port)
            stream_key = tuple(sorted([(packet[IP].src, packet[TCP].sport), (packet[IP].dst, packet[TCP].dport)]))
            # Append packet to appropriate stream
            streams[stream_key].append(packet)

    # Create a list to hold the handshake dictionaries
    handshakes = []

    # Save each stream with a three-way handshake as a dictionary
    for stream_key, stream_packets in streams.items():
        handshake_packets = []
        initial_syn = False
        syn_ack = False
        final_ack = False

        # Find the SYN, SYN-ACK, and ACK packets
        for packet in stream_packets:
            if packet[TCP].flags == 'S':
                initial_syn = True
                handshake_packets.append(packet)
            elif packet[TCP].flags == 'SA':
                if initial_syn and not syn_ack:
                    syn_ack = True
                    handshake_packets.append(packet)
            elif packet[TCP].flags == 'A':
                if initial_syn and syn_ack and not final_ack:
                    final_ack = True
                    handshake_packets.append(packet)

        # If all three flags are present, add the handshake to the list
        if initial_syn and syn_ack and final_ack:
            handshake_data = {
                'id': stream_key,  # Use stream key as the ID
                'text': f"{stream_key[0][0]}:{stream_key[0][1]} -> {stream_key[1][0]}:{stream_key[1][1]}",
                'handshake_packets': [packet_to_dict(packet) for packet in handshake_packets]
            }
            handshakes.append(handshake_data)

    # Create the output folder if it doesn't exist
    output_folder = "pcap_output"
    os.makedirs(output_folder, exist_ok=True)

    # Save the handshakes as a JSON file
    output_file = os.path.join(output_folder, 'handshakes2.json')
    with open(output_file, 'w') as f:
        json.dump(handshakes, f, indent=4, default=str)

# Call the function with the input pcap file name
save_tcp_streams_from_pcap('anyi-060823.pcap')
