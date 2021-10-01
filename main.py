import struct
import textwrap
import socket

TAB_1='\t'
TAB_2='\t\t'
TAB_3='\t\t\t'
TAB_4='\t\t\t\t'

DATA_TAB_1='\t'
DATA_TAB_2='\t\t'
DATA_TAB_3='\t\t\t'
DATA_TAB_4='\t\t\t\t'

def main():
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        rawData, address = connection.recvfrom(65535)
        reciever_mac, sender_mac, ethernetProtocol, data = ethernet_frame(rawData)
        print('\nEthernet Frame: ')
        print(TAB_1+'Destination MAC : {} \n'.format(reciever_mac) + TAB_1 +'Source MAC: {}\n'.format(sender_mac) + TAB_1 + 'Protocol: {}'.format(ethernetProtocol))

        #  8 for IPv4
        if ethernetProtocol == 8:
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
            print('\n' + TAB_1 + 'IPv4 Packet:')
            print(TAB_2 + 'Version: {} \n'.format(version) + TAB_2 + 'Header Length: {}\n'.format(header_length) + TAB_2 + 'TTL: {}\n'.format(ttl))
            print(TAB_2 + 'Protocol: {}\n'.format(proto) + TAB_2 + 'Source IP: {}\n'.format(src) + TAB_2 + 'Target IP: {}\n'.format(target))

            #  ICMP
            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print(TAB_1 + 'ICMP Packet: ')
                print(TAB_2 + 'Type: {}\n'.format(icmp_type) + TAB_2 + 'Code: {}\n'.format(code) + TAB_2 + 'Checksum: {}\n'.format(checksum))
                print(TAB_2 + 'Data: ')
                print(format_multi_line(DATA_TAB_3, data))

            #  TCP
            elif proto == 6:
                src_port, dest_port, sequence, acknowledgement, flag_fin, flag_syn, flag_ack, flag_psh, flag_rst, flag_urg = tcp_segment(data)
                print(TAB_1 + 'TCP Segment :')
                print(TAB_2 + 'Source Port: {}\n'.format(src_port) + TAB_2 + 'Destination Port: {}\n'.format(dest_port))
                print(TAB_2 + 'Sequence: {}\n'.format(sequence) + TAB_2 + 'Acknowledgement: {}\n'.format(acknowledgement))
                print(TAB_2 + 'Flags:')
                print(TAB_3 + 'URG: {}\n'.format(flag_urg) + TAB_3 + 'ACK: {}\n'.format(flag_ack) + TAB_3 + 'PSH: {}\n'.format(flag_psh) + TAB_3 + 'RST: {}\n'.format(flag_rst) + TAB_3 + 'SYN: {}\n'.format(flag_syn) + TAB_3 + 'FIN: {}\n'.format(flag_fin))
                print(TAB_2 + 'Data:')
                print(format_multi_line(DATA_TAB_3, data))      

            #  UDP
            elif proto == 17:   
                src_port, dest_port, length, data = udp_segment(data)
                print(TAB_1 + 'UDP Segment :')
                print(TAB_2 + 'Source Port: {}. Destination Port: {}'.format(src_port,dest_port))
        
            #  Others
            else:
                print(TAB_1 + 'Data: ')
                print(format_multi_line(DATA_TAB_2, data))

        else:
            print('Data: ')
            print(format_multi_line(DATA_TAB_1, data))


# Unpack ethernet frame
def ethernet_frame(data):
    reciever_mac, sender_mac, protocol = struct.unpack('! 6s 6s H', data[:14])
    return getMacAddress(reciever_mac), getMacAddress(sender_mac), socket.htons(protocol), data[14:]

# Convert the Mac address from the jumbled up form from above into human readable format
def getMacAddress(bytesAddress):
    bytesString = map('{:02x}'.format, bytesAddress)
    macAddress = ':'.join(bytesString).upper()
    return macAddress

#  Unpacks IPv4 packet
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

#  Returns properly formatted ipv4 address
def ipv4(addr):
    return '.'.join(map(str, addr))


#  Unpacks ICMP packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

#  Unpacks TCP segment
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 32) >> 4
    flag_psh = (offset_reserved_flags & 32) >> 3
    flag_rst = (offset_reserved_flags & 32) >> 2
    flag_syn = (offset_reserved_flags & 32) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgement, flag_fin, flag_syn, flag_ack, flag_psh, flag_rst, flag_urg

#  Unpacks UDP segment
def udp_segment(data):
    src_port, dest_port, size = struct.unpack("! H H 2x H", data[:8])
    return src_port, dest_port, size, data[8:]

#  Formats multi-line data
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

main()