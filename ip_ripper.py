import pyshark

# Function to extract IP addresses from a pcap file
def extract_ip_addresses(pcap_file):
    unique_ips = set()

    # Read the pcap file
    cap = pyshark.FileCapture(pcap_file)

    for packet in cap:
        # Check if the packet has IP layer
        if 'IP' in packet:
            ip_src = packet.ip.src
            ip_dst = packet.ip.dst
            unique_ips.update([ip_src, ip_dst])
        
        # Check if the packet has IPv6 layer
        if 'IPv6' in packet:
            ipv6_src = packet.ipv6.src
            ipv6_dst = packet.ipv6.dst
            unique_ips.update([ipv6_src, ipv6_dst])

    # Close the capture file
    cap.close()

    return unique_ips

# Function to write IP addresses to a text file
def write_ips_to_file(file_path, ip_addresses):
    with open(file_path, 'w') as file:
        for ip in sorted(ip_addresses):
            file.write(ip + '\n')

# Main function to prompt for input and write output
def main():
    pcap_file = input("Enter the path to the pcap file: ")  # Prompt for pcap file path
    output_file = 'extracted_ips.txt'  # Output file name

    ip_addresses = extract_ip_addresses(pcap_file)
    write_ips_to_file(output_file, ip_addresses)

    print(f"IP addresses extracted and saved to {output_file}")

# Running the main function
if __name__ == "__main__":
    main()
