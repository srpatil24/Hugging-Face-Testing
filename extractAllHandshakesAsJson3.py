import json
import pyshark

def parse_packet(packet):
    try:
        packet_info = {
            'protocol': packet.highest_layer,
            'srcport': str(packet.tcp.srcport) if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'srcport') else None,
            'dstport': str(packet.tcp.dstport) if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'dstport') else None,
            'port': str(packet.tcp.port) if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'port') else None,
            'stream': str(packet.tcp.stream) if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'stream') else None,
            'completeness': str(packet.tcp.completeness) if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'completeness') else None,
            'len': str(packet.tcp.len) if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'len') else None,
            'seq': str(packet.tcp.seq) if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'seq') else None,
            'seq_raw': str(packet.tcp.seq_raw) if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'seq_raw') else None,
            'nxtseq': str(packet.tcp.nxtseq) if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'nxtseq') else None,
            'ack': str(packet.tcp.ack) if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'ack') else None,
            'ack_raw': str(packet.tcp.ack_raw) if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'ack_raw') else None,
            'hdr_len': str(packet.tcp.hdr_len) if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'hdr_len') else None,
            'flags': str(packet.tcp.flags) if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'flags') else None,
            'flags_res': str(packet.tcp.flags_res) if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'flags_res') else None,
            'flags_ae': str(packet.tcp.flags_ae) if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'flags_ae') else None,
            'flags_cwr': str(packet.tcp.flags_cwr) if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'flags_cwr') else None,
            'flags_ece': str(packet.tcp.flags_ece) if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'flags_ece') else None,
            'flags_urg': str(packet.tcp.flags_urg) if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'flags_urg') else None,
            'flags_ack': str(packet.tcp.flags_ack) if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'flags_ack') else None,
            'flags_push': str(packet.tcp.flags_push) if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'flags_push') else None,
            'flags_reset': str(packet.tcp.flags_reset) if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'flags_reset') else None,
            'flags_syn': str(packet.tcp.flags_syn) if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'flags_syn') else None,
            '_ws_expert': str(packet.tcp._ws_expert) if hasattr(packet, 'tcp') and hasattr(packet.tcp, '_ws_expert') else None,
            'connection_syn': str(packet.tcp.connection_syn) if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'connection_syn') else None,
            '_ws_expert_message': str(packet.tcp._ws_expert_message) if hasattr(packet, 'tcp') and hasattr(packet.tcp, '_ws_expert_message') else None,
            '_ws_expert_severity': str(packet.tcp._ws_expert_severity) if hasattr(packet, 'tcp') and hasattr(packet.tcp, '_ws_expert_severity') else None,
            '_ws_expert_group': str(packet.tcp._ws_expert_group) if hasattr(packet, 'tcp') and hasattr(packet.tcp, '_ws_expert_group') else None,
            'flags_fin': str(packet.tcp.flags_fin) if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'flags_fin') else None,
            'flags_str': str(packet.tcp.flags_str) if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'flags_str') else None,
            'window_size_value': str(packet.tcp.window_size_value) if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'window_size_value') else None,
            'window_size': str(packet.tcp.window_size) if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'window_size') else None,
            'checksum': str(packet.tcp.checksum) if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'checksum') else None,
            'checksum_status': str(packet.tcp.checksum_status) if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'checksum_status') else None,
            'urgent_pointer': str(packet.tcp.urgent_pointer) if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'urgent_pointer') else None,
            'options': str(packet.tcp.options) if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'options') else None,
            'options_mss': str(packet.tcp.options_mss) if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'options_mss') else None,
            'option_kind': str(packet.tcp.option_kind) if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'option_kind') else None,
            'option_len': str(packet.tcp.option_len) if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'option_len') else None,
            'options_mss_val': str(packet.tcp.options_mss_val) if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'options_mss_val') else None,
            'options_nop': str(packet.tcp.options_nop) if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'options_nop') else None,
            'options_sack_perm': str(packet.tcp.options_sack_perm) if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'options_sack_perm') else None,
            'time_relative': str(packet.tcp.time_relative) if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'time_relative') else None,
            'time_delta': str(packet.tcp.time_delta) if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'time_delta') else None,
            'Source IP': str(packet.ip.src) if hasattr(packet, 'ip') and hasattr(packet.ip, 'src') else '',
            'Destination IP': str(packet.ip.dst) if hasattr(packet, 'ip') and hasattr(packet.ip, 'dst') else '',
            'time_since_reference': str(packet.frame_info.time_relative),
        }
        return packet_info
    except AttributeError:

        # Ignore packets without any fields
        pass

def pcap_parser(filepath):
    capture = pyshark.FileCapture(filepath, display_filter='(tcp.flags.syn != 0) or (tcp.flags.ack != 0)')
    parsed_packets = [parse_packet(packet) for packet in capture]
    # Remove None values
    #parsed_packets = [packet for packet in parsed_packets if packet]
    return parsed_packets

packets = pcap_parser('fuzz-2006-06-26-2594.pcap')

# Save output as JSON
output_file = 'three_way_handshakes_2.json'

with open(output_file, 'w') as f:
    json.dump(packets, f, indent=4)

print(f"Output saved as {output_file}.")
