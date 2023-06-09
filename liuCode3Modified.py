import os
from scapy.all import *
from collections import defaultdict

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

    # Create the output folder if it doesn't exist
    output_folder = "pcap_output"
    os.makedirs(output_folder, exist_ok=True)

    # Save each stream as a separate pcap file with SYN, SYN-ACK, and ACK packets only
    for i, stream_key in enumerate(streams.keys()):
        stream_packets = streams[stream_key]

        # Check if the stream has a three-way handshake
        if len(stream_packets) >= 3:
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

            # If all three flags are present, save the handshake packets as a pcap file
            if initial_syn and syn_ack and final_ack:
                output_file = os.path.join(output_folder, f'tcp_stream_{i}.pcap')
                wrpcap(output_file, handshake_packets)

# Call the function with the input pcap file name
save_tcp_streams_from_pcap('anyi-060823.pcap')
