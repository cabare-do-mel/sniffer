import socket
import struct
import textwrap

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t  '
DATA_TAB_2 = '\t\t  '
DATA_TAB_3 = '\t\t\t  '
DATA_TAB_4 = '\t\t\t\t  '

def main():
    # Criando o socket  
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\n Ethernet Frame:')
        print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))

        # Protocolo 8 corrensponde ao IPv4
        if eth_proto == 8:
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
            print(TAB_1 + 'IPv4 Packet:')
            print(TAB_2 + 'Version: {}, Header Lenght: {}, TTL: {}'.format(version, header_length, ttl))
            print(TAB_2 + 'Protocol: {}, Souce: {}, Target: {}'.format(proto, src, target))

            #IMCP Protocol
            if proto == 1:
                icmp_type, code, checksum, data = icpm_packet(data)
                print(TAB_1 + 'ICMP Packet:')
                print(TAB_2 + 'Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
                print(TAB_2 + 'Data:')
                print(format_multi_line(DATA_TAB_3, data))

            # TCP Protocol
            elif proto == 6:
                src_port, dest_port, sequence, acknowledgement, flag_ack,flag_fin, flag_psh, flag_rst, flag_syn, flag_urg, data = tcp_segment(data)
                print(TAB_1 + 'TCP Packet:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_mac))
                print(TAB_2 + 'Sequence: {}, Acknowlegement: {}'.format(sequence, acknowledgement))
                print(TAB_2 + 'Flags:')
                print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                print(TAB_2 + 'Data:')
                print(format_multi_line(DATA_TAB_3, data))

            # UDP Protocol
            elif proto == 17:
                src_port, dest_port, length, data = udp_segment(data)
                print(TAB_1 + 'UDP Segment:')
                print(TAB_2 + 'Source: {}, Destination: {}, Length: {}'. format(src_port, dest_port, length))

            # Other
            else:
                print(TAB_1 + 'Data: ')
                print(format_multi_line(DATA_TAB_2, data))
        
        else:
            print('Data:')
            print(format_multi_line(DATA_TAB_1, data))



# Desestruturando pacote ethernet, recebido em binário
# tratando dados para que a forma como eles são armazenados seja a mesma
# data[:14] -> cabeçalho || data[14:]-> payload
# retorna o endereço de destino, o endereco de envio, o protocolo e o payload respectivamente
def ethernet_frame(data):
    mac_destino, mac_fonte, protocolo = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_address(mac_destino), get_mac_address(mac_fonte), socket.htons(protocolo), data[14:]

# Retorna o endereço MAC formatado para leitura
# transforma os bytes em 2 digitos decimais formatados (ex AA:BB:CC:DD:EE:FF)
def get_mac_address(byte_addr):
    bytes_str = map('{:02x}'.format, byte_addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr

# Unpacks IPV4 packets
def ipv4_packet(data):
    version_header_lenth = data[0]
    version = version_header_lenth >> 4
    header_length = (version_header_lenth & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

# Retorna o IPv4 formatado corretamente
def ipv4(adress):
    return '.'.join(map(str, adress))

# Unpacks ICMP (Internet Control Message Protocol) packet
def icpm_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# Trata o seguimento TCP 
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgement, flag_ack,flag_fin, flag_psh, flag_rst, flag_syn, flag_urg, data[offset:]


# Trata o seguimento UDP
def udp_segment(data):
    (src_port, dest_port, length) = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, length, data[8:]


# Formata dados de multiplas linhas 
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


main()