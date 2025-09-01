# Packet Sniffer

A simple Python packet sniffer for Windows and Linux that captures and displays
TCP, UDP, ICMP, and other IP packets in a readable format. A lightweight
Tkinter-based UI (`sniffer_ui.py`) is included to view live output and control
the sniffer process.

## Features
- Captures all packets on your network interface
- Separates TCP, UDP, ICMP, and other protocols
- Displays source/destination IP, TTL, protocol, ports, ICMP info, and payload bytes
- Works on Windows (requires admin) and Linux

## Requirements
- Python 3.8+ (3.x)
- Administrator / root privileges (required for raw sockets)
- Tkinter (usually included with Python on desktop installs)

If you want to avoid raw sockets on Windows, consider using npcap/winpcap
with scapy; that requires different code and drivers.

## Usage

Run the CLI sniffer (for quick tests). You must run as Administrator/root.

Windows (PowerShell as Administrator):
```powershell
cd "D:\Projects\Packet Sniffer"
& "D:/Program Files/python.exe" sniffer.py
```

Linux (root or sudo):
```bash
cd /path/to/project
sudo python3 sniffer.py
```

Run the graphical UI (recommended): it starts the sniffer subprocess and shows
live output with Start/Stop, Clear, Save and Filter controls. Run the UI with
the same elevated privileges so the sniffer subprocess can create raw sockets.

Windows (PowerShell as Administrator):
```powershell
cd "D:\Projects\Packet Sniffer"
& "D:/Program Files/python.exe" sniffer_ui.py
```

Linux:
```bash
cd /path/to/project
sudo python3 sniffer_ui.py
```

## How it works
- Creates a raw socket and (on Windows) enables promiscuous mode
- Parses IP, TCP, UDP, and ICMP headers
- Prints readable info for each packet; the UI streams that output

Files
- `sniffer.py` — command-line packet sniffer (raw sockets)
- `sniffer_ui.py` — simple Tkinter GUI wrapper that runs `sniffer.py`
- `README.md` — this file

Troubleshooting
- PermissionError when creating raw socket: run the script as Administrator
   (Windows) or with `sudo` (Linux). The script will print a clear message and
   exit if it lacks privileges.
- On Windows, ensure Npcap/WinPcap are installed if you later switch to a
   packet-capture library that requires them.

## Example Output
```
[+] IP Packet: 192.168.1.2 -> 192.168.1.1 | TTL: 64 | Protocol: 6
   TCP Segment: 443 -> 51234
   Data (first 40 bytes): 16 03 01 ...
```

## Notes
- This project is intended for learning and authorized network analysis only.
- Always have permission before sniffing network traffic.

## License
MIT
