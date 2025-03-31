Hi everyone. This code is my first python project, so don't be surprised if you see some amateurly made mistakes😅

# Network Packet Sniffer 🚀🔍💻

## Overview ✨📡🔬
This is a simple network packet sniffer written in Python using Scapy. It captures network traffic, analyzes packets, and saves them to a `.pcap` file for further inspection with tools like WireShark. 🦈

## Features 🏆📡📊
- Captures and analyzes Ethernet, IP, TCP, UDP, and ICMP packets. 
- Extracts HTTP request data from captured packets. 
- Displays real-time packet information in the console. 
- Saves captured packets into a `.pcap` file for later analysis. 
- Gracefully terminates and saves packets when interrupted (Ctrl+C). ⏳💾✅

## Prerequisites ⚙️🐍📦
Ensure you have Python installed along with the required dependencies. 🎯📥🔧

### Install Dependencies 📌📂⚡
Run the following command to install Scapy:
```bash
pip install scapy
```

## Usage 🚀🖥️🎯
Run the script with Python:
```bash
python sniff.py
```

Once the script starts, it will capture packets and display their details in the console. To stop capturing and save the packets, press `Ctrl+C`. 🛑💾📊

## Output 📁📜📡
- Captured packets are saved in the `PCAP/` directory with a timestamped `.pcap` file. 
- Console output includes real-time analysis of network traffic. 📊🔍📄

## Example Output 📡💾📝
```plaintext
Ethernet frame
 Source MAC: 00:11:22:33:44:55 --> Destination MAC: 66:77:88:99:AA:BB , Protocol: 2048

IP packet
 Source IP: 192.168.1.10 --> Destination IP: 192.168.1.1 ,  Protocol: 6

TCP segment
 Source Port: 54321 --> Destination Port: 80 , Flags: 18

HTTP Request from 192.168.1.10 to 192.168.1.1
--------------------------------------------------
GET /index.html HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0
--------------------------------------------------
```

## Notes ⚠️📌🔎
- Running this script requires administrative privileges. 
- Ensure that you have the necessary permissions to capture network traffic. 
- This tool is intended for educational and cybersecurity research purposes only. 🔐🛠️📊

## Disclaimer ⚠️🔐🚫
This tool is for ethical use only. The author is not responsible for any misuse or illegal activities involving this script. 🚀🔍🛑

