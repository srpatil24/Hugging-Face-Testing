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
    # Save each stream as a separate pcap file
    for i, stream_key in enumerate(streams.keys()):
        wrpcap(f'tcp_stream_{i}.pcap', streams[stream_key])
# Call the function with the input pcap file name
save_tcp_streams_from_pcap('anyi-060823.pcap')