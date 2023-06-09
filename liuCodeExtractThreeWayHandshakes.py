import os
import json
from scapy.all import *
from dpkt.pcap import Reader
from dpkt.tcp import TCP, TH_SYN, TH_ACK
import dpkt


def sanitize_filename(filename):
    # Remove special characters from the filename
    return re.sub(r'[<>:"/\\|?*]', '', filename)

def extract_sessions(pcap_file):
    save_directory = os.path.join(os.getcwd(), "pcap_output")  # Absolute path to save pcap files
    os.makedirs(save_directory, exist_ok=True)  # Create the directory if it doesn't exist
    sessions = rdpcap(pcap_file).sessions()
    for session in sessions:
        session_name = sanitize_filename(session)
        pcap_path = os.path.join(save_directory, session_name + ".pcap")
        wrpcap(pcap_path, sessions[session])


def extract_handshake(pcap_file):
    handshake_packets = []
    with open(pcap_file, "rb") as f:
        pcap = Reader(f)
        for timestamp, packet in pcap:
            eth = dpkt.ethernet.Ethernet(packet)
            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data
                if isinstance(ip.data, TCP):
                    tcp = ip.data
                    if (tcp.flags & TH_SYN) and not (tcp.flags & TH_ACK):
                        handshake_packets.append(packet)
                    elif (tcp.flags & TH_SYN) and (tcp.flags & TH_ACK):
                        handshake_packets.append(packet)
                    elif not (tcp.flags & TH_SYN) and (tcp.flags & TH_ACK):
                        handshake_packets.append(packet)
                        break
    return handshake_packets

def tokenize_packets(packets):
    tokenized = []
    for packet in packets:
        eth = dpkt.ethernet.Ethernet(packet)
        ip = eth.data
        tcp = ip.data
        tokenized.append({
            "eth_src": eth.src,
            "eth_dst": eth.dst,
            "ip_src": ip.src,
            "ip_dst": ip.dst,
            "tcp_sport": tcp.sport,
            "tcp_dport": tcp.dport,
            "tcp_seq": tcp.seq,
            "tcp_ack": tcp.ack,
            "tcp_flags": tcp.flags
        })
    return tokenized

def main():
    pcap_file = "fuzz-2006-06-26-2594.pcap"
    handshake_packets = extract_handshake(pcap_file)

    # Convert handshake packets to a JSON-serializable format
    tokenized_packets = []
    for packet in handshake_packets:
        tokenized_packet = {
            "data": packet.hex()
        }
        tokenized_packets.append(tokenized_packet)

    # Save tokenized packets to a JSON file
    output_file = "pcap_output/tokenized_packets.json"
    with open(output_file, "w") as f:
        json.dump(tokenized_packets, f)

if __name__ == "__main__":
    main()