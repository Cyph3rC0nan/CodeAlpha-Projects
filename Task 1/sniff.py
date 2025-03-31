from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP, Raw, wrpcap
import signal
import sys
import datetime
import os

timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
all_packets = []
# Creates a folder named PCAP if not exist and save the capture inside a .pcap file in it
folder = "PCAP"
if not os.path.exists(folder):
    os.makedirs(folder)

PCAP_File = os.path.join(folder, f"capture_{timestamp}.pcap")

# Format all the packets
def format_data(data):
    if Ether in data:
        eth = data[Ether]
        print(f"Ethernet frame\n Source MAC: {eth.src} --> Destination MAC: {eth.dst} , Protocol: {eth.type}\n")

    if IP in data:
        ip = data[IP]
        print(f"IP packet\n Source IP: {ip.src} --> Destination IP: {ip.dst} ,  Protocol: {ip.proto}\n")

    if TCP in data:
        tcp = data[TCP]
        print(f"TCP segment\n Source Port: {tcp.sport} --> Destination Port: {tcp.dport} , Flags: {tcp.flags}\n")
        if tcp.dport == 80 and Raw in data:
            http_data = data[Raw].load.decode(errors="ignore")
            if "HTTP" in http_data:
                print(f"HTTP Request from {data[IP].src} to {data[IP].dst}\n")
                print("-" * 50 + "\n")
                print(f"{http_data}\n")
                print("-" * 50 + "\n")

    if UDP in data:
        udp = data[UDP]
        print(f"UDP datagram\n Source Port: {udp.sport} --> Destination Port: {udp.dport}\n")

    if ICMP in data:
        icmp = data[ICMP]
        print("ICMP Echo packet")
        if icmp.type == 8:
            print(f"Echo request from {data[IP].src} to {data[IP].dst}\n")
        if icmp.type == 0:
            print(f"Echo reply from {data[IP].src} to {data[IP].dst}\n")

    all_packets.append(data)

# Save the packets to a PCAP file
def save_pcap(signal, frame):
    print("\n[+] Terminating the program and saving the captured packets to a PCAP file.")
    wrpcap(PCAP_File, all_packets)  
    print(f"[+] Packets saved to {PCAP_File}. Exiting...")
    sys.exit(0)

# Start sniffing
def main():
    signal.signal(signal.SIGINT, save_pcap)

    print(f"{timestamp} - Starting sniffing...\n")
    sniff(prn=format_data, store=False)

if __name__ == '__main__':
    main()