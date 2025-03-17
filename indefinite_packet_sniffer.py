from scapy.all import sniff, IP, TCP, UDP, Ether, Raw, wrpcap

def packet_callback(packet):
    try:
        # Extract Ethernet layer information
        if Ether in packet:
            src_mac = packet[Ether].src
            dst_mac = packet[Ether].dst
            print(f"Ethernet: Source MAC: {src_mac}, Destination MAC: {dst_mac}")

        # Extract IP layer information
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            print(f"IP: Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {protocol}")

            # Extract TCP layer information
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                print(f"TCP: Source Port: {src_port}, Destination Port: {dst_port}")

            # Extract UDP layer information
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                print(f"UDP: Source Port: {src_port}, Destination Port: {dst_port}")

            # Extract and decode payload data
            if packet.haslayer(Raw):
                payload = packet[Raw].load
                try:
                    # Try to decode the payload as UTF-8
                    decoded_payload = payload.decode('utf-8', errors='replace')
                    print(f"Decoded Payload: {decoded_payload}")
                except Exception as e:
                    # If decoding fails, display the raw bytes
                    print(f"Payload (Raw): {payload}")

        print("-" * 50)  # Separator for readability

    except Exception as e:
        print(f"Error processing packet: {e}")

def start_sniffing(interface=None, save_to_file=False):
    print(f"Starting packet sniffer on interface: {interface}")
    print("Press Ctrl+C to stop the program...")

    if save_to_file:
        # Capture packets indefinitely and store them in a list
        packets = sniff(iface=interface, prn=packet_callback, store=True)
        
        # Save the captured packets to a file
        wrpcap("captured_packets.pcap", packets)
        print("Packets saved to captured_packets.pcap")
    else:
        # Just capture and display packets without saving
        sniff(iface=interface, prn=packet_callback)

if __name__ == "__main__":
    # Specify the network interface to sniff on (e.g., "eth0" or "wlan0")
    interface = "eth0"  # Change this to your network interface

    # Set to True to save packets to a file
    save_to_file = True

    # Start sniffing
    try:
        start_sniffing(interface=interface, save_to_file=save_to_file)
    except KeyboardInterrupt:
        print("\nPacket sniffer stopped by the user.")