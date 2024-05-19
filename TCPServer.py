import struct
import socket
from scapy.all import IP, TCP, Raw
from TCP_seg import TCP_seg, compute_checksum, verify_checksum
import random
import time


class TCP:
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
        self.num = 0
    
    def update_state(self, new_state):
        self.state = new_state
        print(f"{self.num} New State: {self.state}")
        self.num += 1
    
    @staticmethod
    def _get_next_seq(tcp_seg):
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
        if tcp_seg.data:
            return tcp_seg.seq_num + len(tcp_seg.data)
        elif flags['SYN'] or flags['FIN']:
            return tcp_seg.seq_num + 1
        else:
            return tcp_seg.seq_num

    def _send(self, flags, data=b''):
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
        
        

    def _send_syn(self):
        self.update_state("SYN_SENT")
        self.seq_num = random.randint(0, 10000)
        print(f">>SEQ {self.seq_num}:Sending SYN to {self.dst_ip}:{self.dst_port}")
        
        self._send(flags=2) # SYN

    def _send_ack(self, flags, data=b''):
        flags = flags | 16 # ACK
        print(f">>SEQ {self.seq_num}:Sending ACK: {self.ack_num} to {self.dst_ip}:{self.dst_port}")
        self._send(flags=flags, data=data)

    def connect(self, dst_ip, dst_port):
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        print(f"Connecting to {self.dst_ip}:{self.dst_port}")
        self._send_syn()

    def bind(self, src_ip, src_port):
        self.src_ip = src_ip
        self.src_port = src_port
        self.sock.bind((self.src_ip, self.src_port))
        self.update_state("LISTEN")
        print(f"Listening on {self.src_ip}:{self.src_port}")

    def handle(self, data, src_ip):
        tcp_seg = TCP_seg().unpack(data)
        if not verify_checksum(tcp_seg, socket.inet_aton(self.dst_ip), socket.inet_aton(self.src_ip)):
            print("Checksum failed")
            return
        if tcp_seg.ack_num != self.seq_num:
            print("*************************")
            print("ACK number does not match")
            print(f"ACK: {tcp_seg.ack_num} != {self.seq_num}")
            print("*************************")
            
            return
        self.ack_num = max(self._get_next_seq(tcp_seg), self.ack_num)
        

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

        print(f"<<SEQ:{tcp_seg.seq_num}:Receiving ACK: {tcp_seg.ack_num} from {src_ip}:{tcp_seg.src_port}")

        if tcp_seg.data:
            self.recv_buf += tcp_seg.data
            print(f"Received: {tcp_seg.data.decode()}")
            self._send_ack()
        elif flags['RST']:
            self._close()
        elif flags['SYN']: # SYN 
            if self.state == "SYN_SENT":
                self.update_state("ESTABLISHED")
                self._send_ack(flags=0)
            elif self.state == "LISTEN":
                self.update_state("SYN_RECEIVED")
                
                self.src_ip = src_ip
                self.dst_port = tcp_seg.src_port

                self._send_ack(flags=2) # SYN ACK

        elif flags['FIN']:
            if self.state == "FIN_WAIT_2":
                self.update_state("TIME_WAIT")
                self._send_ack()
                self._close()
            elif self.state == "ESTABLISHED":
                # skip close_wait
                self.update_state("LAST_ACK")
                self._send_ack(flags=1) # FIN ACK

        elif flags['ACK']:
            if self.state == "FIN_WAIT_1":
                self.seq_num=self.seq_num+1
                self.update_state("FIN_WAIT_2")
            elif self.state == "LAST_ACK":
                self._close()
            elif self.state == "SYN_RECEIVED":
                self.update_state("ESTABLISHED")
                
        else:
            print("*************************")
            print("Unknown state")
            print(f"Flags: {flags}")
            print(f"Curr State: {self.state}")
            print("*************************")

    def send(self, data):
        while self.state != "ESTABLISHED":
            time.sleep(0.5)
            print("Waiting for connection")
        self._send_ack(flags=8, data=data) # PSH
            
    def recv(self, size, timeout=0):
        start = time.time()
        tcp_seg = TCP_seg()
        while self.state!="CLOSED":
            data, addr = self.sock.recvfrom(1024)
            tcp_seg = TCP_seg().unpack(data)
            self.handle(data, addr[0])
            
        """data = self.recv_buf[:size]
        print(f"Received: {data}")
        self.recv_buf = self.recv_buf[size:]
        return data"""

    def _close(self):
        self.update_state("CLOSED")
        self.sock.close()
    
    def close(self):
        if self.state == "CLOSED":
            return
        self.update_state("FIN_WAIT_1")
        self._send(flags=1) # FIN


if __name__ == "__main__":
    server = TCP(src_ip='127.0.0.1', dst_ip='127.0.0.1', src_port=12345, dst_port=54321)
    server.bind(src_ip='127.0.0.1', src_port=12345)
    server.recv(size=1024)
