import struct
import socket
from scapy.all import IP, TCP, Raw
from TCP_seg import TCP_seg, compute_checksum
import random


class TCPClient:
    def __init__(self, src_ip, dst_ip, src_port, dst_port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.seq_num = 0
        self.ack_num = 0
        
        self.state = "CLOSED"
        self.num = 0
    
    def update_state(self, new_state):
        self.state = new_state
        print(f"{self.num} New State: {self.state}")
        self.num += 1

    def send_syn(self):
        self.seq_num = random.randint(0, 10000)
        syn_seg = TCP_seg(
            src_port=self.src_port,
            dst_port=self.dst_port,
            seq_num=self.seq_num,
            ack_num=0,
            data_offset=5<<4,
            reserved=0,
            flags=2, # syn
            window_size=4096,
            checksum=0,
            urgent_pointer=0,
            options=b'',
            data=b''
        )
        syn_seg = syn_seg.pack(socket.inet_aton(self.src_ip), socket.inet_aton(self.dst_ip))
        self.sock.sendto(syn_seg, (self.dst_ip, self.dst_port))

    def receive_syn_ack(self):
        data, addr = self.sock.recvfrom(1024)
        tcp_seg = TCP_seg().unpack(data)
        if tcp_seg.flags == 18: # syn, ack
            self.ack_num = tcp_seg.seq_num + 1
            self.seq_num += 1
            self.send_ack()
    
    def send_ack(self):
        ack_seg = TCP_seg(
            src_port=self.src_port,
            dst_port=self.dst_port,
            seq_num=self.seq_num,
            ack_num=self.ack_num,
            data_offset=5<<4,
            reserved=0,
            flags=16, # ack b1000
            window_size=4096,
            checksum=0,
            urgent_pointer=0,
            options=b'',
            data=b''
        )
        ack_seg = ack_seg.pack(socket.inet_aton(self.src_ip), socket.inet_aton(self.dst_ip))
        self.sock.sendto(ack_seg, (self.dst_ip, self.dst_port))

    def receive_ack(self):
        data, addr = self.sock.recvfrom(1024)
        tcp_seg = TCP_seg().unpack(data)
        if tcp_seg.flags == 16: # ack
            self.ack_num = tcp_seg.seq_num + 1

    def send_fin(self):
        fin_seg = TCP_seg(
            src_port=self.src_port,
            dst_port=self.dst_port,
            seq_num=self.seq_num,
            ack_num=self.ack_num,
            data_offset=5<<4,
            reserved=0,
            flags=1, # fin
            window_size=4096,
            checksum=0,
            urgent_pointer=0,
            options=b'',
            data=b''
        )
        fin_seg = fin_seg.pack(socket.inet_aton(self.src_ip), socket.inet_aton(self.dst_ip))
        self.sock.sendto(fin_seg, (self.dst_ip, self.dst_port))

    def receive_fin(self):
        data, addr = self.sock.recvfrom(1024)
        tcp_seg = TCP_seg().unpack(data)
        if tcp_seg.flags == 1:
            self.ack_num = tcp_seg.seq_num + 1
            self.send_ack()

    def close(self):
        self.send_fin()
        self.update_state("FIN_WAIT_1")
        self.receive_ack()
        self.update_state("FIN_WAIT_2")
        self.receive_fin()
        self.update_state("TIME_WAIT")
        # time wait for 2MSL
        self.update_state("CLOSED")

    def connect(self):
        self.send_syn()
        self.update_state("SYN_SENT")
        self.receive_syn_ack()
        self.update_state("ESTABLISHED")
    
    def send_data(self, data):
        data_seg = TCP_seg(
            src_port=self.src_port,
            dst_port=self.dst_port,
            seq_num=self.seq_num,
            ack_num=self.ack_num,
            data_offset=5<<4,
            reserved=0,
            flags=24, # psh, ack b0000 11000
            window_size=4096,
            checksum=0,
            urgent_pointer=0,
            options=b'',
            data=data
        )
        data_seg = data_seg.pack(socket.inet_aton(self.src_ip), socket.inet_aton(self.dst_ip))
        self.sock.sendto(data_seg, (self.dst_ip, self.dst_port))
        self.seq_num += len(data)
    
    def receive_data(self):
        data, addr = self.sock.recvfrom(1024)
        tcp_seg = TCP_seg().unpack(data)
        if tcp_seg.flags == 24: # psh, ack
            print(f"Received data: {tcp_seg.data.decode()}")
            self.ack_num = tcp_seg.seq_num + len(tcp_seg.data)
            self.send_ack()
            return tcp_seg.data
        return None

        
        
    