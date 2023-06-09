import json
import pandas as pd

def load_handshake_data(file_path):
    with open(file_path, 'r') as f:
        handshakes = json.load(f)
    return handshakes

def create_handshake_table(handshakes):
    table_data = []
    for handshake in handshakes:
        stream_key = handshake['stream_key']
        handshake_packets = handshake['handshake_packets']

        for i in range(len(handshake_packets) - 2):
            syn_packet = handshake_packets[i]
            syn_ack_packet = handshake_packets[i + 1]
            ack_packet = handshake_packets[i + 2]

            row_1 = {
                'ID': f"{stream_key[0][0]}:{stream_key[0][1]}_{stream_key[1][0]}:{stream_key[1][1]}_{i}",
                'Context/0': syn_packet['packet_data'],
                'Context': syn_ack_packet['packet_data'],
                'Response': ack_packet['packet_data']
            }
            row_2 = {
                'ID': f"{stream_key[0][0]}:{stream_key[0][1]}_{stream_key[1][0]}:{stream_key[1][1]}_{i+1}",
                'Context/0': '',
                'Context': syn_packet['packet_data'],
                'Response': syn_ack_packet['packet_data']
            }

            table_data.append(row_1)
            table_data.append(row_2)

    handshake_table = pd.DataFrame(table_data)
    return handshake_table

handshakes = load_handshake_data('pcap_output/handshakes.json')
handshake_table = create_handshake_table(handshakes)
handshake_table.to_csv('handshake_table.csv', index=False)
