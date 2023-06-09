from scapy.all import rdpcap, wrpcap, TCP
import os

def extract_sessions(pcap_file):
    packets = rdpcap(pcap_file)
    sessions = packets.sessions()
    
    output_folder = "pcap_output"  # Output folder name
    
    # Create the output folder if it doesn't exist
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
    
    for session_index, session in enumerate(sessions):
        # Check the protocol of the first packet in the session
        first_packet = sessions[session][0]
        if first_packet.haslayer(TCP):
            filename = f'{output_folder}/TCP_session_{session_index}.pcap'
        else:
            filename = f'{output_folder}/non-TCP_session_{session_index}.pcap'

        wrpcap(filename, sessions[session])

extract_sessions('fuzz-2006-06-26-2594.pcap')
