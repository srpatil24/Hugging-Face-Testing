import json
import pyshark

def parse_packet(packet):
    try:
        packet_info = {
            'srcport': str(packet.tcp.srcport),
            'dstport': str(packet.tcp.dstport),
            'port': str(packet.tcp.port),
            'stream': str(packet.tcp.stream),
            'completeness': str(packet.tcp.completeness),
            'len': str(packet.tcp.len),
            'seq': str(packet.tcp.seq),
            'seq_raw': str(packet.tcp.seq_raw),
            'nxtseq': str(packet.tcp.nxtseq),
            'ack': str(packet.tcp.ack),
            'ack_raw': str(packet.tcp.ack_raw),
            'hdr_len': str(packet.tcp.hdr_len),
            'flags': str(packet.tcp.flags),
            'flags_res': str(packet.tcp.flags_res),
            'flags_ae': str(packet.tcp.flags_ae),
            'flags_cwr': str(packet.tcp.flags_cwr),
            'flags_ece': str(packet.tcp.flags_ece),
            'flags_urg': str(packet.tcp.flags_urg),
            'flags_ack': str(packet.tcp.flags_ack),
            'flags_push': str(packet.tcp.flags_push),
            'flags_reset': str(packet.tcp.flags_reset),
            'flags_syn': str(packet.tcp.flags_syn),
            '_ws_expert': str(packet.tcp._ws_expert),
            'connection_syn': str(packet.tcp.connection_syn),
            '_ws_expert_message': str(packet.tcp._ws_expert_message),
            '_ws_expert_severity': str(packet.tcp._ws_expert_severity),
            '_ws_expert_group': str(packet.tcp._ws_expert_group),
            'flags_fin': str(packet.tcp.flags_fin),
            'flags_str': str(packet.tcp.flags_str),
            'window_size_value': str(packet.tcp.window_size_value),
            'window_size': str(packet.tcp.window_size),
            'checksum': str(packet.tcp.checksum),
            'checksum_status': str(packet.tcp.checksum_status),
            'urgent_pointer': str(packet.tcp.urgent_pointer),
            'options': str(packet.tcp.options),
            'options_mss': str(packet.tcp.options_mss),
            'option_kind': str(packet.tcp.option_kind),
            'option_len': str(packet.tcp.option_len),
            'options_mss_val': str(packet.tcp.options_mss_val),
            'options_nop': str(packet.tcp.options_nop),
            'options_sack_perm': str(packet.tcp.options_sack_perm),
            'time_relative': str(packet.tcp.time_relative),
            'time_delta': str(packet.tcp.time_delta),
            'Source IP': str(packet.ip.src),
            'Destination IP': str(packet.ip.dst),
        }
        return packet_info
    except AttributeError:
        # Ignore packets without any fields
        pass

def pcap_parser(filepath):
    capture = pyshark.FileCapture(filepath)
    parsed_packets = [parse_packet(packet) for packet in capture if 'tcp' in packet]
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
