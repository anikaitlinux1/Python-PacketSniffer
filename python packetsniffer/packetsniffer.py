import socket
import struct
import textwrap



TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '


def main():
    conn = socket.socket(socket.AF_PACKET,socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac,src_mac,eth_proto,data=ethernet_frame(raw_data)
        print("\nEthernet Frame: ")
        print('Destination: {}, Source: {}, Protocol: {}'.format(dest_mac,src_mac,eth_proto))

    # 8 for IPv4
    if eth_proto==8:
        (version,header_len,ttl,proto,src,target,data)=ipv4_packet(data)
        print(TAB_1+'IPv4 Packet: ')
        print(TAB_2+'Version: {}, Header Length: {}, TTL: {}'.format(version,header_len,ttl))
        print(TAB_2+'Protocol: {}, Source: {}, Target: {}'.format(proto,src,target))

        #ICMP
        if proto==1:
            icmp_type,code,checksum,data=icmp_packet(data)
            print(TAB_1+'ICMP Packet: ')
            print(TAB_2+'Type: {}, Code: {}, Checksum: {}'.format(icmp_type,code,checksum))
            print(TAB_2+'Data: {}')
            print(format_multi_line(DATA_TAB_3,data))
        
        #TCP
        elif proto==6:
            src_port,dest_port,sequence,acknowledgement,flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin,data=tcp_segment(data)
            print(TAB_1+'TCP SEGMENT: ')
            print(TAB_2+'Source Port: {}, Destination Port: {}'.format(src_port,dest_port))
            print(TAB_2+'Sequence: {}, Acknowledgement: {} '.format(sequence,acknowledgement))
            print(TAB_2+ 'Flags: ')
            print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}'.format(tcp.flag_urg, tcp.flag_ack, tcp.flag_psh))
            print(TAB_3 + 'RST: {}, SYN: {}, FIN:{}'.format(tcp.flag_rst, tcp.flag_syn, tcp.flag_fin))
            print(format_multi_line(DATA_TAB_3,data))

        # UDP
        elif ipv4.proto == 17:
            udp = UDP(ipv4.data)
            print(TAB_1 + 'UDP Segment:')
            print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(udp.src_port, udp.dest_port, udp.size))

        # Other IPv4
        else:
            print(TAB_1 + 'Other IPv4 Data:')
            print(format_multi_line(DATA_TAB_2, ipv4.data))

    else:
        print('Ethernet Data:')
        print(format_multi_line(DATA_TAB_1, eth.data))



#to unpack the ethernet framework
def ethernet_frame(data):
    mac_destination,mac_source,proto = struct.unpack('! 6s 6s H', data[:14])
    return get_macaddress(mac_destination), get_macaddress(mac_source), socket.htons(proto), data[14:]

#to show the formatted MAC address (AA:BB:CC:DD:EE:FF)
def get_macaddress(bytes_address):
    bytes_str=map('{:02x}'.format,bytes_address)
    mac_address=':'.join(bytes_str).upper()
    return mac_address

#unpacking ipv4 packet
def ipv4_packets(data):
    version_header_len=data[0]
    version=version_header_len >> 4
    header_len=(version_header_len & 15)*4
    ttl,proto,src,target=struct.unpack('! 8x B B 2x 4s 4s',data[:20])
    return version,header_len,ttl,proto,ipv4(src),ipv4(target),data[header_len]

#returns properly formatted ipv4 address
def ipv4(addr):
    return '.'.join(map(str,addr))

#unpacks icmp packet
def icmp_packet(data):
    icmp_type,code,checksum=struct.unpack('! B B H',data[:4])
    return icmp_type,code,checksum,data[4:]

#unpacks TCP segment
def tcp_segment(data):
    (src_port,dest_port,sequence,acknowledgement,offset_res_flags)=struct.unpack('! H H L L H',data[:14])
    offset=(offset_res_flags >> 12)*4
    flag_urg=(offset_res_flags & 32) >> 5
    flag_ack=(offset_res_flags & 16) >> 4
    flag_psh=(offset_res_flags & 8) >> 3
    flag_rst=(offset_res_flags & 4) >> 2
    flag_syn=(offset_res_flags & 2) >> 1
    flag_fin=offset_res_flags & 1

    return src_port,dest_port,sequence,acknowledgement,flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin,data[offset:]

#Unpacks UDP segment
def udp_segment(data):
    src_port,dest_port,size=struct.unpack('! H H 2X H',data[:8])
    return  src_port,dest_port,size,data[8:]

#Formatting multi-line data
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


main()