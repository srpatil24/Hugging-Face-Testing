import json
import pyshark

def parse_packet(packet):
    packet_info = {
        'protocol': packet.highest_layer,
        'srcport': '',
        'dstport': '',
        'port': '',
        'stream': '',
        'completeness': '',
        'len': '',
        'seq': '',
        'seq_raw': '',
        'nxtseq': '',
        'ack': '',
        'ack_raw': '',
        'hdr_len': '',
        'flags': '',
        'flags_res': '',
        'flags_ae': '',
        'flags_cwr': '',
        'flags_ece': '',
        'flags_urg': '',
        'flags_ack': '',
        'flags_push': '',
        'flags_reset': '',
        'flags_syn': '',
        '_ws_expert': '',
        'connection_syn': '',
        '_ws_expert_message': '',
        '_ws_expert_severity': '',
        '_ws_expert_group': '',
        'flags_fin': '',
        'flags_str': '',
        'window_size_value': '',
        'window_size': '',
        'checksum': '',
        'checksum_status': '',
        'urgent_pointer': '',
        'options': '',
        'options_mss': '',
        'option_kind': '',
        'option_len': '',
        'options_mss_val': '',
        'options_nop': '',
        'options_sack_perm': '',
        'time_relative': '',
        'time_delta': '',
        'Source IP': str(packet.ip.src),
        'Destination IP': str(packet.ip.dst),
    }

def parse_packet(packet):
    packet_info = {
        'protocol': packet.highest_layer,
        'srcport': '',
        'dstport': '',
        'port': '',
        'stream': '',
        'completeness': '',
        'len': '',
        'seq': '',
        'seq_raw': '',
        'nxtseq': '',
        'ack': '',
        'ack_raw': '',
        'hdr_len': '',
        'flags': '',
        'flags_res': '',
        'flags_ae': '',
        'flags_cwr': '',
        'flags_ece': '',
        'flags_urg': '',
        'flags_ack': '',
        'flags_push': '',
        'flags_reset': '',
        'flags_syn': '',
        '_ws_expert': '',
        'connection_syn': '',
        '_ws_expert_message': '',
        '_ws_expert_severity': '',
        '_ws_expert_group': '',
        'flags_fin': '',
        'flags_str': '',
        'window_size_value': '',
        'window_size': '',
        'checksum': '',
        'checksum_status': '',
        'urgent_pointer': '',
        'options': '',
        'options_mss': '',
        'option_kind': '',
        'option_len': '',
        'options_mss_val': '',
        'options_nop': '',
        'options_sack_perm': '',
        'time_relative': '',
        'time_delta': '',
        'Source IP': '',
        'Destination IP': '',
    }

    # Extract IP information if available
    if 'ip' in packet.layers:
        ip_layer = packet.ip
        packet_info['Source IP'] = str(ip_layer.src)
        packet_info['Destination IP'] = str(ip_layer.dst)

    # Iterate over available fields and add them dynamically to packet_info
    for field in dir(packet):
        if not field.startswith('_') and field != 'frame_info':
            packet_info[field] = str(getattr(packet, field))

    return packet_info


def pcap_parser(filepath):
    capture = pyshark.FileCapture(filepath)
    parsed_packets = [parse_packet(packet) for packet in capture]
    # Remove None values
    parsed_packets = [packet for packet in parsed_packets if packet]
    return parsed_packets

# Replace 'test.pcap' with your pcap file
packets = pcap_parser('fuzz-2006-06-26-2594.pcap')

# Save output as JSON
output_file = 'all.json'

with open(output_file, 'w') as f:
    json.dump(packets, f, indent=4)

print(f"Output saved as {output_file}.")