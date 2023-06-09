import json
import sys
import getopt
from scapy.all import rdpcap, TCP
from scapy.layers.inet import IP
from tqdm import tqdm

def extract_handshakes(pcap_file):
    packets = rdpcap(pcap_file)
    handshakes = []

    # Initialize the tqdm progress bar
    progress_bar = tqdm(total=len(packets), desc="Processing packets", unit="packet")

    # Iterate over packets and extract three-way handshakes
    for index in range(len(packets)):
        packet = packets[index]
        progress_bar.update(1)  # Update the progress bar

        if TCP in packet and packet[TCP].flags.S and not packet[TCP].flags.A:
            client_syn = packet[TCP].payload.original
            server_syn_ack = None
            client_ack = None

            # Find corresponding SYN-ACK and ACK packets
            for p in packets[index:]:
                if (
                    TCP in p
                    and p[IP].src == packet[IP].dst
                    and p[IP].dst == packet[IP].src
                    and p[TCP].flags.S and p[TCP].flags.A
                ):
                    server_syn_ack = p[TCP].payload.original
                    break

            for p in packets[index:]:
                if (
                    TCP in p
                    and p[IP].src == packet[IP].dst
                    and p[IP].dst == packet[IP].src
                    and not p[TCP].flags.S and p[TCP].flags.A
                ):
                    client_ack = p[TCP].payload.original
                    break

            # Add the handshake to the list
            if server_syn_ack and client_ack:
                try:
                    handshake = {
                        'client_syn': client_syn.decode('utf-8', 'ignore'),
                        'server_syn_ack': server_syn_ack.decode('utf-8', 'ignore'),
                        'client_ack': client_ack.decode('utf-8', 'ignore')
                    }
                    handshakes.append(handshake)
                except UnicodeDecodeError:
                    pass

    progress_bar.close()  # Close the progress bar
    print("Extracted Handshakes:", handshakes)
    return handshakes


def generate_json_file(handshakes, json_file):
    data = {
        'personas': [],
        'additional_context': '',
        'previous_utterance': [],
        'context': 'wizard_of_wikipedia',
        'free_messages': [],
        'guided_messages': [],
        'suggestions': {
            'convai2': [],
            'empathetic_dialogues': [],
            'wizard_of_wikipedia': []
        },
        'guided_chosen_suggestions': [],
        'label_candidates': []
    }

    # Initialize the tqdm progress bar
    progress_bar = tqdm(total=len(handshakes), desc="Generating JSON", unit="handshake")

    for handshake in handshakes:
        progress_bar.update(1)  # Update the progress bar

        data['previous_utterance'].append(handshake['client_syn'])
        data['previous_utterance'].append(handshake['server_syn_ack'])
        data['previous_utterance'].append(handshake['client_ack'])

        data['free_messages'].append('')
        data['guided_messages'].append('')

        data['suggestions']['convai2'].append('')
        data['suggestions']['empathetic_dialogues'].append('')
        data['suggestions']['wizard_of_wikipedia'].append('')

        data['guided_chosen_suggestions'].append('')
        data['label_candidates'].append([])

    progress_bar.close()  # Close the progress bar

    with open(json_file, 'w') as file:
        json.dump(data, file)


# Default file names
pcap_file = '202301011400.pcap'
json_file = '3WayHandshakeData.json'

# Parse command-line options
try:
    opts, args = getopt.getopt(sys.argv[1:], "i:o:")
except getopt.GetoptError:
    print("Invalid command-line options. Usage: python your_script.py -i input.pcap -o output.json")
    sys.exit(2)

# Process command-line options
for opt, arg in opts:
    if opt == '-i':
        pcap_file = arg
    elif opt == '-o':
        json_file = arg


handshakes = extract_handshakes(pcap_file)
generate_json_file(handshakes, json_file)
