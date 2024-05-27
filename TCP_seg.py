import struct
import socket
from scapy.all import IP, TCP, Raw
import random

def compute_checksum(data):
        # make data length even
        if len(data) % 2:
            data += b'\0'

        chksum = 0

        # 0, 2, 4, 6, ...
        for i in range(0, len(data), 2):
            # concatenate 2 bytes = 16bits
            chksum += (data[i] << 8) + data[i+1]
            # if exceed 16 bits (carry), add to lower 16 bits (wraparound)
            chksum += (chksum >> 16)
            # make sure it's 16 bits
            chksum &= 0xffff

        # one's complement
        return ~chksum & 0xffff

def recompute_checksum(tcp_seg, src_ip, dst_ip):
    src_ip = src_ip
    dst_ip = dst_ip
    reserved = 0
    protocal = socket.IPPROTO_TCP
    checksum = tcp_seg.checksum
    tcp_seg.checksum = 0

    tcp_header = struct.pack('!HHLLBBHHH',
                                tcp_seg.src_port, tcp_seg.dst_port, #  HH
                                tcp_seg.seq_num, # L
                                tcp_seg.ack_num, # L
                                (tcp_seg.data_offset << 4) | tcp_seg.reserved, # 16 BB
                                tcp_seg.flags, tcp_seg.window_size,            # 16 H
                                tcp_seg.checksum, tcp_seg.urgent_pointer) # HH
    
    total_length = len(tcp_header) + len(tcp_seg.data)

    pseudo_header = struct.pack('!4s4sBBH',
                                src_ip, dst_ip, 
                                reserved, protocal, 
                                total_length)

    pseudo_header += tcp_header + tcp_seg.data
    tcp_seg.checksum = checksum
    return compute_checksum(pseudo_header)

def verify_checksum(tcp_seg, src_ip, dst_ip, verbose=False):
    src_ip = src_ip
    dst_ip = dst_ip
    reserved = 0
    protocal = socket.IPPROTO_TCP
    checksum = tcp_seg.checksum
    tcp_seg.checksum = 0

    tcp_header = struct.pack('!HHLLBBHHH',
                                tcp_seg.src_port, tcp_seg.dst_port, #  HH
                                tcp_seg.seq_num, # L
                                tcp_seg.ack_num, # L
                                (tcp_seg.data_offset << 4) | tcp_seg.reserved, # 16 BB
                                tcp_seg.flags, tcp_seg.window_size,            # 16 H
                                tcp_seg.checksum, tcp_seg.urgent_pointer) # HH
    
    total_length = len(tcp_header) + len(tcp_seg.data)

    pseudo_header = struct.pack('!4s4sBBH',
                                src_ip, dst_ip, 
                                reserved, protocal, 
                                total_length)

    pseudo_header += tcp_header + tcp_seg.data
    tcp_seg.checksum = checksum
    return compute_checksum(pseudo_header) == checksum


class TCP_seg:
    def __init__(self, **kwargs):
        if kwargs == {}:
            kwargs = {
                'src_port': 0,
                'dst_port': 0,
                'seq_num': 0,
                'ack_num': 0,
                'data_offset': 5<<4,
                'reserved': 0,
                'flags': 0,
                'window_size': 0,
                'checksum': 0,
                'urgent_pointer': 0,
                'options': b'',
                'data': b''
            }
        #1
        self.src_port = kwargs['src_port']
        self.dst_port = kwargs['dst_port']
        #2
        self.seq_num = kwargs['seq_num']
        #3
        self.ack_num = kwargs['ack_num']
        #4
        self.data_offset = kwargs['data_offset']
        self.reserved = 0
        self.flags = kwargs['flags']
        self.window_size = kwargs['window_size']
        #5
        self.checksum = kwargs['checksum']
        self.urgent_pointer = kwargs['urgent_pointer']

        self.options = kwargs['options']
        self.data = kwargs['data']
    
    def __str__(self):
        return f"TCP Segment from port {self.src_port} to {self.dst_port}, Seq: {self.seq_num}, Ack: {self.ack_num}, Flags: {bin(self.flags)}"

    def pack(self, src_ip, dst_ip):
        #print(f"packed with src_ip: {src_ip}, dst_ip: {dst_ip}")
        self.data_offset = 5+(len(self.options)>>2)
        # H: (2), L: (4), B: (1)
        self.checksum=0
        tcp_header = struct.pack('!HHLLBBHHH',
                                 self.src_port, self.dst_port, #  HH
                                 self.seq_num, # L
                                 self.ack_num, # L
                                 (self.data_offset << 4) | self.reserved, # 16 BB
                                 self.flags, self.window_size,            # 16 H
                                 self.checksum, self.urgent_pointer) # HH
        
        src_ip = src_ip
        dst_ip = dst_ip
        reserved = 0
        protocal = socket.IPPROTO_TCP
        total_length = len(tcp_header) + len(self.data)
        
        # 4s: 4 bytes string (4)
        pseudo_header = struct.pack('!4s4sBBH',
                                    src_ip, dst_ip, 
                                    reserved, protocal, 
                                    total_length)
        pseudo_header += tcp_header + self.data
        self.checksum = compute_checksum(pseudo_header)
        tcp_header = struct.pack('!HHLLBBHHH',
                                 self.src_port, self.dst_port, #  HH
                                 self.seq_num, # L
                                 self.ack_num, # L
                                 (self.data_offset << 4) | self.reserved, # 16 BB
                                 self.flags, self.window_size,            # 16 H
                                 self.checksum, self.urgent_pointer)
        if self.checksum != recompute_checksum(self, src_ip, dst_ip):
            print("Checksum Error")
            print(f"    Expected: {recompute_checksum(self, src_ip, dst_ip)}")
            print(f"    Received: {self.checksum}")

        return tcp_header + self.options + self.data


    
    def unpack(self, packet):
        tcp_header = struct.unpack('!HHLLBBHHH', packet[:20])
        self.src_port = tcp_header[0]
        self.dst_port = tcp_header[1]
        self.seq_num = tcp_header[2]
        self.ack_num = tcp_header[3]
        self.data_offset = tcp_header[4] >> 4
        #self.reserved = tcp_header[4] 
        self.flags = tcp_header[5]
        self.window_size = tcp_header[6]
        self.checksum = tcp_header[7]
        self.urgent_pointer = tcp_header[8]
        self.options = packet[20:self.data_offset*4]
        self.data = packet[self.data_offset*4:]
        
        return self

        
if __name__ == "__main__":
    kwargs = {
        'src_ip': '192.168.0.1',
        'dst_ip': '192.168.0.0',
        'src_port': 12345,
        'dst_port': 80,
        'seq_num': 0,
        'ack_num': 0,
        'data_offset': 5<<4,
        'reserved': 0,
        'flags': 2, # syn
        'window_size': 4096,
        'checksum': 0,
        'urgent_pointer': 0,
        'options': b'',
        'data': b''
    }
    syn_seg = TCP_seg(**kwargs)
    syn_seg = syn_seg.pack(socket.inet_aton(kwargs['src_ip']), socket.inet_aton(kwargs['dst_ip']))
    syn_seg = TCP_seg().unpack(syn_seg)
    print(verify_checksum(syn_seg, socket.inet_aton(kwargs['src_ip']), socket.inet_aton(kwargs['dst_ip'])))