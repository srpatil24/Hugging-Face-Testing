import os
from scapy.all import *
import json

def packet_to_dict(packet):
    # Convert the packet to a dictionary representation
    packet_dict = {
        'timestamp': packet.time,
        'source': packet[IP].src,
        'destination': packet[IP].dst,
        'sport': packet[TCP].sport,
        'dport': packet[TCP].dport,
        'flags': packet[TCP].flags,
        'seq': packet[TCP].seq,
        'ack': packet[TCP].ack,
        'window': packet[TCP].window,
        'checksum': packet[TCP].chksum,
        'urgent_pointer': packet[TCP].urgptr,
        'options': packet[TCP].options,
        'payload': str(packet[TCP].payload),
        'length': len(packet),
        'ip_version': packet[IP].version,
        'ip_ttl': packet[IP].ttl,
        'ip_id': packet[IP].id,
        'ip_proto': packet[IP].proto,
        'ip_flags': packet[IP].flags,
        'ip_tos': packet[IP].tos,
        'ip_ihl': packet[IP].ihl,
        'ip_options': packet[IP].options,
        'eth_source': packet[Ether].src,
        'eth_destination': packet[Ether].dst,
        'eth_type': packet[Ether].type,
        'icmp_type': packet[ICMP].type if 'ICMP' in packet else None,
        'icmp_code': packet[ICMP].code if 'ICMP' in packet else None,
        'icmp_payload': str(packet[ICMP].payload) if 'ICMP' in packet else None,
        'udp_source': packet[UDP].sport if 'UDP' in packet else None,
        'udp_destination': packet[UDP].dport if 'UDP' in packet else None,
        'udp_length': packet[UDP].len if 'UDP' in packet else None,
        'udp_checksum': packet[UDP].chksum if 'UDP' in packet else None,
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
                    final_ack=True
                    handshake_packets.append(packet)

        # If all three flags are present, add the handshake to the list
        if initial_syn and syn_ack and final_ack:
            # Create two rows for the handshake session
            row1 = {
                'Response': packet_to_dict(handshake_packets[2]),  # ACK packet
                'Context': packet_to_dict(handshake_packets[1]),   # SYN-ACK packet
                'Context/0': packet_to_dict(handshake_packets[0])  # SYN packet
            }
            row2 = {
                'Response': packet_to_dict(handshake_packets[1]),  # SYN-ACK packet
                'Context': packet_to_dict(handshake_packets[0]),   # SYN packet
                'Context/0': None                                  # Empty for row 2
            }

            handshakes.append(row1)
            handshakes.append(row2)

    # Create the output folder if it doesn't exist
    output_folder = "pcap_output"
    os.makedirs(output_folder, exist_ok=True)

    # Save the handshakes as a JSON file
    output_file = os.path.join(output_folder, 'handshakes3.json')
    with open(output_file, 'w') as f:
        json.dump(handshakes, f, indent=4, default=str)

# Call the function with the input pcap file name
save_tcp_streams_from_pcap('anyi-060823.pcap')