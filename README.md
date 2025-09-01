# Packet Sniffer

A simple Python packet sniffer for Windows and Linux that captures and displays TCP, UDP, ICMP, and other IP packets in a readable format.

## Features
- Captures all packets on your network interface
- Separates TCP, UDP, ICMP, and other protocols
- Displays source/destination IP, TTL, protocol, ports, ICMP info, and payload bytes
- Works on Windows (requires admin) and Linux

## Requirements
- Python 3.x
- Administrator/root privileges (required for raw sockets)

## Usage
1. Open a terminal as Administrator (Windows) or use `sudo` (Linux)
2. Navigate to the project directory:
   ```powershell
   cd "D:\Projects\Packet Sniffer"
   ```
3. Run the sniffer:
   ```powershell
   & "D:/Program Files/python.exe" sniffer.py
   ```
   Or on Linux:
   ```bash
   sudo python3 sniffer.py
   ```

## How it works
- Creates a raw socket and enables promiscuous mode
- Parses IP, TCP, UDP, and ICMP headers
- Prints readable info for each packet

## Example Output
```
[+] IP Packet: 192.168.1.2 -> 192.168.1.1 | TTL: 64 | Protocol: 6
    TCP Segment: 443 -> 51234
    Data (first 40 bytes): 16 03 01 ...
```

## Notes
- On Windows, you must run as Administrator for raw sockets and promiscuous mode
- On Linux, root privileges are required

## License
MIT
