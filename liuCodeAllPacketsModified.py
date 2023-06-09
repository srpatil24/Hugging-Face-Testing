import json
import pyshark

def parse_packet(packet):
    try:
        packet_info = {
            'protocol': packet.highest_layer,
            'srcport': str(packet.tcp.srcport) if 'tcp' in packet else '',
            'dstport': str(packet.tcp.dstport) if 'tcp' in packet else '',
            'port': str(packet.tcp.port) if 'tcp' in packet else '',
            'stream': str(packet.tcp.stream) if 'tcp' in packet else '',
            'completeness': str(packet.tcp.completeness) if 'tcp' in packet else '',
            'len': str(packet.tcp.len) if 'tcp' in packet else '',
            'seq': str(packet.tcp.seq) if 'tcp' in packet else '',
            'seq_raw': str(packet.tcp.seq_raw) if 'tcp' in packet else '',
            'nxtseq': str(packet.tcp.nxtseq) if 'tcp' in packet else '',
            'ack': str(packet.tcp.ack) if 'tcp' in packet else '',
            'ack_raw': str(packet.tcp.ack_raw) if 'tcp' in packet else '',
            'hdr_len': str(packet.tcp.hdr_len) if 'tcp' in packet else '',
            'flags': str(packet.tcp.flags) if 'tcp' in packet else '',
            'flags_res': str(packet.tcp.flags_res) if 'tcp' in packet else '',
            'flags_ae': str(packet.tcp.flags_ae) if 'tcp' in packet else '',
            'flags_cwr': str(packet.tcp.flags_cwr) if 'tcp' in packet else '',
            'flags_ece': str(packet.tcp.flags_ece) if 'tcp' in packet else '',
            'flags_urg': str(packet.tcp.flags_urg) if 'tcp' in packet else '',
            'flags_ack': str(packet.tcp.flags_ack) if 'tcp' in packet else '',
            'flags_push': str(packet.tcp.flags_push) if 'tcp' in packet else '',
            'flags_reset': str(packet.tcp.flags_reset) if 'tcp' in packet else '',
            'flags_syn': str(packet.tcp.flags_syn) if 'tcp' in packet else '',
            '_ws_expert': str(packet.tcp._ws_expert) if 'tcp' in packet else '',
            'connection_syn': str(packet.tcp.connection_syn) if 'tcp' in packet else '',
            '_ws_expert_message': str(packet.tcp._ws_expert_message) if 'tcp' in packet else '',
            '_ws_expert_severity': str(packet.tcp._ws_expert_severity) if 'tcp' in packet else '',
            '_ws_expert_group': str(packet.tcp._ws_expert_group) if 'tcp' in packet else '',
            'flags_fin': str(packet.tcp.flags_fin) if 'tcp' in packet else '',
            'flags_str': str(packet.tcp.flags_str) if 'tcp' in packet else '',
            'window_size_value': str(packet.tcp.window_size_value) if 'tcp' in packet else '',
            'window_size': str(packet.tcp.window_size) if 'tcp' in packet else '',
            'checksum': str(packet.tcp.checksum) if 'tcp' in packet else '',
            'checksum_status': str(packet.tcp.checksum_status) if 'tcp' in packet else '',
            'urgent_pointer': str(packet.tcp.urgent_pointer) if 'tcp' in packet else '',
            'options': str(packet.tcp.options) if 'tcp' in packet else '',
            'options_mss': str(packet.tcp.options_mss) if 'tcp' in packet else '',
            'option_kind': str(packet.tcp.option_kind) if 'tcp' in packet else '',
            'option_len': str(packet.tcp.option_len) if 'tcp' in packet else '',
            'options_mss_val': str(packet.tcp.options_mss_val) if 'tcp' in packet else '',
            'options_nop': str(packet.tcp.options_nop) if 'tcp' in packet else '',
            'options_sack_perm': str(packet.tcp.options_sack_perm) if 'tcp' in packet else '',
            'time_relative': str(packet.tcp.time_relative) if 'tcp' in packet else '',
            'time_delta': str(packet.tcp.time_delta) if 'tcp' in packet else '',
            'Source IP': str(packet.ip.src) if 'ip' in packet else '',
            'Destination IP': str(packet.ip.dst) if 'ip' in packet else '',
            'time_since_reference': str(packet.frame_info.time_relative),
        }
        return packet_info
    except AttributeError:
        # Ignore packets without any fields
        pass

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