import struct
import socket
from TCP_seg import TCP_seg, compute_checksum, verify_checksum
import random
import time
import datetime
import builtins

class TCPSocket:
    def __init__(self, src_ip, dst_ip, src_port, dst_port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.seq_num = 0
        self.ack_num = 0

        self.recv_buf = b''
        self.state = "CLOSED"
        self.connections = []
    
    def update_state(self, new_state):
        self.state = new_state
        print(f"Server State: {self.state}")

    def bind(self, src_ip, src_port):
        self.src_ip = src_ip
        self.src_port = src_port
        self.sock.bind((src_ip, src_port))
        self.update_state("LISTEN")
        print(f"Server is listening on {src_ip}:{src_port}")
    
    def accept(self):
        while True:
            data, addr = self.sock.recvfrom(1024)
            tcp_seg = TCP_seg().unpack(data)
            flags = {
                'FIN': (tcp_seg.flags & 1) == 1,
                'SYN': (tcp_seg.flags & 2) == 2,
                'RST': (tcp_seg.flags & 4) == 4,
                'PSH': (tcp_seg.flags & 8) == 8,
                'ACK': (tcp_seg.flags & 16) == 16,
                'URG': (tcp_seg.flags & 32) == 32,
                'ECE': (tcp_seg.flags & 64) == 64,
                'CWR': (tcp_seg.flags & 128) == 128
            }
            if not verify_checksum(tcp_seg, socket.inet_aton(addr[0]), socket.inet_aton(self.src_ip)):
                print("Checksum failed")
                return None
            
            for x in self.connections:
                if x.src_ip == addr[0] and x.src_port == addr[1]:
                    return x
                
            if flags['SYN']:
                conn = Connection(self.sock, self.src_ip, addr[0], self.src_port, addr[1])
                self.connections.append(conn)
                conn.update_state("LISTEN")
                while conn.state != "ESTABLISHED":
                    conn.handshake(client=False, syn_seg=tcp_seg)
                return conn
        
    def connect(self, dst_ip, dst_port):
        conn = Connection(self.sock, self.src_ip, dst_ip, self.src_port, dst_port)
        while conn.state != "ESTABLISHED":
            conn.handshake()
        return conn

class Connection:
    def __init__(self,sock ,src_ip, dst_ip, src_port, dst_port):
        self.sock = sock if sock else socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.seq_num = 0
        self.ack_num = 0

        self.recv_buf = b''
        
        self.state = "CLOSED"
    
    @staticmethod
    def _get_next_seq(tcp_seg):
        if tcp_seg.data:
            return tcp_seg.seq_num + len(tcp_seg.data)
        else:
            return tcp_seg.seq_num + 1

    @staticmethod
    def _get_flag_num(flags):
        table = {
            'FIN': 1,
            'SYN': 2,
            'RST': 4,
            'PSH': 8,
            'ACK': 16,
            'URG': 32,
            'ECE': 64,
            'CWR': 128
        }
        return sum([table[flag] for flag in flags])

    def update_state(self, new_state):
        self.state = new_state
        print(f"({self.state})")

    def _send(self, flags=[], data=b''):
        if self.seq_num == 0:
            self.seq_num = random.randint(0, 10000)

        print(f"    sent: ACK {self.ack_num} SEQ {self.seq_num} >>> {self.dst_ip}:{self.dst_port}")
        # convert string flags to int
        flags = self._get_flag_num(flags)
        tcp_seg = TCP_seg(
            src_port=self.src_port,
            dst_port=self.dst_port,
            seq_num=self.seq_num,
            ack_num=self.ack_num,
            data_offset=5<<4,
            reserved=0,
            flags=flags,
            window_size=4096,
            checksum=0,
            urgent_pointer=0,
            options=b'',
            data=data
        )
        self.seq_num = self._get_next_seq(tcp_seg)
        tcp_seg = tcp_seg.pack(socket.inet_aton(self.src_ip), socket.inet_aton(self.dst_ip))
        self.sock.sendto(tcp_seg, (self.dst_ip, self.dst_port))
    
    def _recv(self, size):
        data, addr = self.sock.recvfrom(size)
        tcp_seg = TCP_seg().unpack(data)
        self.ack_num = tcp_seg.seq_num + 1
        print(f"    receive: ACK {tcp_seg.ack_num} SEQ {tcp_seg.seq_num} <<< {addr[0]}:{addr[1]}")
        if not verify_checksum(tcp_seg, socket.inet_aton(addr[0]), socket.inet_aton(self.src_ip)):
            print("Checksum failed")
            return None
        return tcp_seg

    def handshake(self, client=True, syn_seg=None):
        if client:
            if self.state == "CLOSED":
                self._send(flags=['SYN'])
                self.update_state("SYN_SENT")
            elif self.state == "SYN_SENT":
                tcp_seg = self._recv(1024)
                while not tcp_seg:
                    tcp_seg = self._recv(1024)

                if tcp_seg.flags == 18:
                    self._send(flags=['ACK'])
                    self.update_state("ESTABLISHED")
        else:
            if self.state == "CLOSED":
                return
            elif self.state == "LISTEN":
                tcp_seg = syn_seg

                if tcp_seg.flags == 2:
                    self._send(flags=['SYN', 'ACK'])
                    self.update_state("SYN_RCVD")
                elif tcp_seg.flags == 16:
                    self.update_state("ESTABLISHED")
            elif self.state == "SYN_RCVD":
                tcp_seg = self._recv(1024)
                while not tcp_seg:
                    tcp_seg = self._recv(1024)
                if tcp_seg.flags == 16:
                    self.update_state("ESTABLISHED")
    
    def _handle_close(self, tcp_seg):
        if tcp_seg.flags == 1: # FIN
            self._send(flags=['ACK'])
            self.update_state("CLOSE_WAIT")
            time.sleep(2)
            self._send(flags=['FIN'])
        tcp_seg = self._recv(1024)
        while not tcp_seg:
            tcp_seg = self._recv(1024)

        if tcp_seg.flags == 16:
            self.update_state("CLOSED")

    def close(self):
        self._send(flags=['FIN'])
        self.update_state("FIN_WAIT_1")
        tcp_seg = self._recv(1024)
        while not tcp_seg:
            tcp_seg = self._recv(1024)
        if tcp_seg.flags == 16:
            self.update_state("FIN_WAIT_2")
        tcp_seg = self._recv(1024)
        while not tcp_seg:
            tcp_seg = self._recv(1024)
        if tcp_seg.flags == 1:
            self._send(flags=['ACK'])
            self.update_state("TIME_WAIT")
            time.sleep(2)
            self.update_state("CLOSED")

        

    def send(self, data):
        self._send(flags=['ACK'], data=data)
    
    def recv(self, size):
        tcp_seg = self._recv(size)
        flags = {
            'FIN': (tcp_seg.flags & 1) == 1,
            'SYN': (tcp_seg.flags & 2) == 2,
            'RST': (tcp_seg.flags & 4) == 4,
            'PSH': (tcp_seg.flags & 8) == 8,
            'ACK': (tcp_seg.flags & 16) == 16,
            'URG': (tcp_seg.flags & 32) == 32,
            'ECE': (tcp_seg.flags & 64) == 64,
            'CWR': (tcp_seg.flags & 128) == 128
        }
        print(f"    Received data with size {len(tcp_seg.data)}")
        if flags['FIN']:
            self._handle_close(tcp_seg)
        return tcp_seg.data
    