import pyshark
import json

def pcap_to_json(pcap_file, output_file):
    # Open the pcap file for reading
    capture = pyshark.FileCapture(pcap_file)

    # Initialize a list to store packet data
    packets = []

    # Iterate over each packet in the capture
    for packet in capture:
        # Extract relevant packet information
        packet_data = {
            'frame_number': packet.frame_info.number,
            'timestamp': packet.frame_info.time_epoch,
            'source_ip': packet.ip.src,
            'destination_ip': packet.ip.dst,
            'protocol': packet.layers[1].layer_name  # Assuming IP is the second layer
        }
        # Append the packet data to the list
        packets.append(packet_data)

    # Close the capture
    capture.close()

    # Write the packet data to a JSON file
    with open(output_file, 'w') as file:
        json.dump(packets, file, indent=4)

    print(f"Conversion completed. Results saved to {output_file}.")

# Example usage
pcap_file = 'handshake.pcap'
output_file = 'handshake.json'
pcap_to_json(pcap_file, output_file)
