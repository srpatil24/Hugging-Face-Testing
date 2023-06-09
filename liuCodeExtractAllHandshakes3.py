from scapy.all import rdpcap, wrpcap, TCP
import os

def extract_three_way_handshakes(pcap_file):
    packets = rdpcap(pcap_file)
    sessions = packets.sessions()
    
    output_folder = "pcap_output"  # Output folder name
    
    # Create the output folder if it doesn't exist
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
    
    for session_index, session in enumerate(sessions):
        session_packets = sessions[session]

        # Check if the session has at least 3 packets
        if len(session_packets) >= 3:
            # Check if the first three packets are part of a three-way handshake
            first_packet = session_packets[0]
            second_packet = session_packets[1]
            third_packet = session_packets[2]
            if (
                first_packet.haslayer(TCP)
                and second_packet.haslayer(TCP)
                and third_packet.haslayer(TCP)
                and first_packet[TCP].flags.S
                and second_packet[TCP].flags.SA
                and third_packet[TCP].flags.A
            ):
                filename = f'{output_folder}/3WH_session_{session_index}.pcap'
                wrpcap(filename, session_packets)

extract_three_way_handshakes('fuzz-2006-06-26-2594.pcap')
