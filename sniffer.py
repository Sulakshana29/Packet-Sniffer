import socket
import struct


def format_bytes(data):
    """
    Format bytes to hex for readability.
    Example: b'\x01\x02' -> '01 02'
    """
    return ' '.join(f'{b:02x}' for b in data)


def parse_ip_header(data):
    """
    Parse IP header and return version, header length, TTL, protocol,
    source IP, destination IP.
    """
    ip_header = struct.unpack('!BBHHHBBH4s4s', data[:20])
    version = ip_header[0] >> 4
    ihl = (ip_header[0] & 0xF) * 4
    ttl = ip_header[5]
    protocol = ip_header[6]
    src_ip = socket.inet_ntoa(ip_header[8])
    dst_ip = socket.inet_ntoa(ip_header[9])
    return version, ihl, ttl, protocol, src_ip, dst_ip


def parse_tcp_header(data):
    """
    Parse TCP header and return source and destination ports.
    """
    src_port, dst_port = struct.unpack('!HH', data[:4])
    return src_port, dst_port


def parse_udp_header(data):
    """
    Parse UDP header and return source and destination ports.
    """
    src_port, dst_port = struct.unpack('!HH', data[:4])
    return src_port, dst_port


# Create raw socket
sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
host = socket.gethostbyname(socket.gethostname())
sniffer.bind((host, 0))
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# Enable promiscuous mode (Windows only)
try:
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
except AttributeError:
    pass

print(f"[*] Sniffing on {host}... Press Ctrl+C to stop")

try:
    while True:
        raw_data, addr = sniffer.recvfrom(65535)
        version, ihl, ttl, protocol, src_ip, dst_ip = parse_ip_header(raw_data)

        print(f"\n[+] IP Packet: {src_ip} -> {dst_ip} | TTL: {ttl} | "
              f"Protocol: {protocol}")

        if protocol == 6:  # TCP
            src_port, dst_port = parse_tcp_header(raw_data[ihl:])
            print(f"    TCP Segment: {src_port} -> {dst_port}")
            print(f"    Data (first 40 bytes): "
                  f"{format_bytes(raw_data[ihl+20:ihl+60])}")
        elif protocol == 17:  # UDP
            src_port, dst_port = parse_udp_header(raw_data[ihl:])
            print(f"    UDP Segment: {src_port} -> {dst_port}")
            print(f"    Data (first 40 bytes): "
                  f"{format_bytes(raw_data[ihl+8:ihl+48])}")
        elif protocol == 1:  # ICMP
            icmp_type, code, checksum = struct.unpack(
                '!BBH', raw_data[ihl:ihl+4])
            print(f"    ICMP Packet: Type {icmp_type} | Code {code} | "
                  f"Checksum {checksum}")
            print(f"    Data (first 40 bytes): "
                  f"{format_bytes(raw_data[ihl+4:ihl+44])}")
        else:
            print(f"    Other Protocol Data (first 40 bytes): "
                  f"{format_bytes(raw_data[ihl:ihl+40])}")

except KeyboardInterrupt:
    print("\n[*] Stopping sniffer...")
    try:
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
    except AttributeError:
        pass
