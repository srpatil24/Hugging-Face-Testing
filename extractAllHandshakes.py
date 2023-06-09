import os
from scapy.all import *

def save_handshake_packets(packets, output_file):
    wrpcap(output_file, packets)

def process_pcap(input_file):
    packets = rdpcap(input_file)
    handshake_packets = []
    handshake_count = 0

    for packet in packets:
        if packet.haslayer(TCP) and packet[TCP].flags == "S" and packet[TCP].ack == 0:
            syn_ack_packet = None
            ack_packet = None

            for p in packets:
                if p.haslayer(TCP) and p[TCP].flags == "SA" and p[TCP].ack == packet[TCP].seq + 1 and p.dport == packet.sport and p.sport == packet.dport:
                    syn_ack_packet = p
                    break

            if syn_ack_packet:
                for p in packets:
                    if p.haslayer(TCP) and p[TCP].flags == "A" and p[TCP].ack == syn_ack_packet[TCP].seq + 1 and p.dport == packet.dport and p.sport == packet.sport:
                        ack_packet = p
                        break

            if syn_ack_packet and ack_packet:
                handshake_packets.extend([packet, syn_ack_packet, ack_packet])
                handshake_count += 1
                output_filename = os.path.join("pcap_output", f"handshake_{handshake_count}.pcap")
                save_handshake_packets(handshake_packets, output_filename)
                handshake_packets = []

    if handshake_count > 0:
        print(f"{handshake_count} Three-Way Handshake(s) saved in pcap_output folder")
    else:
        print("No Three-Way Handshakes found")

# Replace 'input.pcap' with the path to your input pcap file
process_pcap('fuzz-2006-06-26-2594.pcap')
