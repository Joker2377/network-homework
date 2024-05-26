import struct
import socket
from TCP_seg import TCP_seg, compute_checksum, verify_checksum
import random
import time
import datetime
import builtins
import threading
import sys


class TCPSocket:
    def __init__(self, src_ip, dst_ip, src_port, dst_port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(5)
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.seq_num = 0
        self.ack_num = 0

        self.recv_buf = b''
        self.state = "CLOSED"
        self.connections = []

        self.glob_recv_buf = []
        self.glob_recv_buf_lock = threading.Lock()
        self.listening = True
        self.sending = True

        self.udp_buf = []
        self.udp_buf_lock = threading.Lock()

        self.conn_rec = 0
    
        self.start_threads()

    def update_state(self, new_state):
        self.state = new_state
        print(f"Server State: {self.state}")

    def start_threads(self):
        self.t_recv = threading.Thread(target=self._recv, args=(1024,))
        self.t_send = threading.Thread(target=self._send)
        self.t_remove = threading.Thread(target=self._remove_closed_connections)
        self.t_udp_recv = threading.Thread(target=self._recvfrom)
        self.t_recv.start()
        self.t_send.start()
        self.t_remove.start()
        self.t_udp_recv.start()

    def _remove_closed_connections(self):
        while self.listening:
            if not self.connections:
                time.sleep(0.01)
                continue
            for conn in self.connections:
                if conn.state == "CLOSED":
                    self.connections.remove(conn)

    def _send(self):
        while self.sending:
            for conn in self.connections:
                if conn.send_buf:
                    with conn.send_buf_lock:
                        data, addr = conn.send_buf.pop(0)
                        self.sock.sendto(data, addr)

    def _recvfrom(self):
        while self.listening:
            try:
                data, addr = self.sock.recvfrom(1024)
                with self.udp_buf_lock:
                    self.udp_buf.append((data, addr))
            except socket.timeout:
                continue
            # handle close
            except socket.error as e:
                break

    def _recv(self, size):
        while self.listening:
            if self.udp_buf:
                with self.udp_buf_lock:
                    if self.udp_buf:
                        data, addr = self.udp_buf.pop(0)
                    else:
                        continue
            else:
                continue
            not_conn = True
            for conn in self.connections:
                if conn.dst_ip == addr[0] and conn.dst_port == addr[1]:
                    conn.append_unhandled((data, addr))
                    not_conn = False
                    break
                
            if not_conn:
                self.conn_rec += 1
                with self.glob_recv_buf_lock:
                    self.glob_recv_buf.append((data, addr))

    def _get_glob_recv_buf(self):
        while not self.glob_recv_buf:
            time.sleep(0.00001) # make sure it wont cause starvation
        with self.glob_recv_buf_lock:
            if self.glob_recv_buf:
                return self.glob_recv_buf.pop(0)
            return None

    def bind(self, src_ip, src_port):
        self.src_ip = src_ip
        self.src_port = src_port
        self.sock.bind((src_ip, src_port))
        self.update_state("LISTEN")
        print(f"Server is listening on {src_ip}:{src_port}")
    
    def accept(self):
        data, addr = self._get_glob_recv_buf()
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
            if x.dst_ip == addr[0] and x.dst_port == addr[1]:
                return x
        print(f"    receive: ACK {tcp_seg.ack_num} SEQ {tcp_seg.seq_num} <<< {addr[0]}:{addr[1]}")
        print(f"(Connection from {addr[0]}:{addr[1]})")
        if flags['SYN']:
            conn_num = addr[1]
            conn = Connection(self.src_ip, addr[0], self.src_port, addr[1], conn_num)
            
            conn.update_state("LISTEN")
            self.connections.append(conn)
            conn.handshake(client=False, syn_seg=tcp_seg)
            
            return conn

    def connect(self, dst_ip, dst_port):
        conn = Connection(self.src_ip, dst_ip, self.src_port, dst_port)
        self.connections.append(conn)
        while conn.state != "ESTABLISHED":
            conn.handshake()
        return conn

    def close(self):
        self.sending = False
        self.listening = False
        for conn in self.connections:
            conn.close()
        self.sock.close()
        if self.t_recv.is_alive():
            self.t_recv.join()
        if self.t_send.is_alive():
            self.t_send.join()
        if self.t_remove.is_alive():
            self.t_remove.join()
        print("Socket closed")
        sys.exit(0)

class Connection:
    def __init__(self, src_ip, dst_ip, src_port, dst_port, conn_num=0):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.seq_num = 0
        self.ack_num = 0

        self.last_acked = 0

        
        self.state = "CLOSED"

        self.inflight_buf = []
        self.recv_buf = []
        self.unhandled_buf = []
        self.send_buf = []
        self.cwnd = 1
        self.threshold = 64
        self.mss = 1024

        self.listening = True
        self.recv_buf_lock = threading.Lock()
        self.unhandled_buf_lock = threading.Lock()
        self.send_buf_lock = threading.Lock()
    

        self.start_recv_thread()

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

    @staticmethod
    def print_seg(tcp_seg):
        print("*"*10)
        print(f"    src_port: {tcp_seg.src_port}")
        print(f"    dst_port: {tcp_seg.dst_port}")
        print(f"    seq_num: {tcp_seg.seq_num}")
        print(f"    ack_num: {tcp_seg.ack_num}")
        print(f"    data_offset: {tcp_seg.data_offset}")
        print(f"    reserved: {tcp_seg.reserved}")
        print(f"    flags: {tcp_seg.flags}")
        print(f"    window_size: {tcp_seg.window_size}")
        print(f"    checksum: {tcp_seg.checksum}")
        print(f"    urgent_pointer: {tcp_seg.urgent_pointer}")
        print(f"    options: {tcp_seg.options}")
        print(f"    data: {tcp_seg.data[:10]}...truncated")
        print("*"*10)
    
    def update_state(self, new_state):
        self.state = new_state
        print(f"({self.state})")

    def _send(self, flags=[], data=b''):
        if self.seq_num == 0:
            self.seq_num = random.randint(0, 10000)
        print("    sent: ", end="")
        print(*flags, sep=", ", end=" : ")
        print(f"ACK {self.ack_num} SEQ {self.seq_num}: {len(data)} bytes")
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
        self.inflight_buf.append((self.seq_num, tcp_seg))
        self.seq_num = self._get_next_seq(tcp_seg)
        tcp_seg = tcp_seg.pack(socket.inet_aton(self.src_ip), socket.inet_aton(self.dst_ip))
        with self.send_buf_lock:
            self.send_buf.append((tcp_seg, (self.dst_ip, self.dst_port)))
    
    def start_recv_thread(self):
        self.t = threading.Thread(target=self._recv, args=(1024,))
        self.t.start()

    def terminate(self):
        # terminate thread
        self.listening = False # useless since it's not global 
        print(f"Terminating connection with {self.dst_ip}:{self.dst_port}")
        if self.t and self.t.is_alive():
            self.t.join()
        print(f"Connection with {self.dst_ip}:{self.dst_port} terminated")
    
    def append_unhandled(self, data):
        with self.unhandled_buf_lock:
            self.unhandled_trigger = True
            self.unhandled_buf.append(data)

    def _recvfrom(self):
        while not self.unhandled_buf:
            time.sleep(0.0001)
            if not self.listening:
                return None, None
        with self.unhandled_buf_lock:
            if self.unhandled_buf:
                if len(self.unhandled_buf) == 1:
                    self.unhandled_trigger = False
                return self.unhandled_buf.pop(0)
            return None

    def _recv(self, size):
        while self.listening:
            data, addr = self._recvfrom()
            if not data:
                continue
            tcp_seg = TCP_seg().unpack(data)
            if not verify_checksum(tcp_seg, socket.inet_aton(addr[0]), socket.inet_aton(self.src_ip)):
                print(f"    Checksum failed")
                print(f"    Expected checksum: {compute_checksum(tcp_seg.pack(socket.inet_aton(self.src_ip), socket.inet_aton(self.dst_ip)))}")
                print(f"    Received checksum: {tcp_seg.checksum}")
                # show two segments comparison table (left, right)
                print(f"    Seq_num: {tcp_seg.seq_num} == {self.ack_num}")
                print(f"    Ack_num: {tcp_seg.ack_num} == {self.seq_num}")
                print()
                self.print_seg(tcp_seg)
                continue
            
            if tcp_seg.seq_num > self.ack_num and self.ack_num!=0:
                print(f"    Expected SEQ {self.ack_num} but got SEQ {tcp_seg.seq_num}")
                continue

            self.ack_num = max(self.ack_num, self._get_next_seq(tcp_seg)) # their seq
            self.last_acked = tcp_seg.ack_num # my seq

            if self.inflight_buf:
                self.inflight_buf = [(seq, seg) for seq, seg in self.inflight_buf if seq >= self.last_acked]
            
            self.cwnd = self.cwnd + 1 if self.cwnd < self.threshold else self.cwnd + 1/self.cwnd
            
            # list of flags raised
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
            flags = [k for k, v in flags.items() if v]
            print("    receive: ", end="")
            print(*flags, sep=", ", end=" : ")
            print(f"ACK {tcp_seg.ack_num} SEQ {tcp_seg.seq_num}: {len(tcp_seg.data)} bytes")
            print(f"(cwnd: {self.cwnd*self.mss} MSS: {self.mss} threshold: {self.threshold})")
            # don't ack fin, syn
            if tcp_seg.data:
                self._send(flags=['ACK'])

            with self.recv_buf_lock:
                self.recv_buf.append(tcp_seg)
            #print(f"    buf: {len(self.recv_buf)}")

    def _get_recv_buf(self):
        # pop the front
        with self.recv_buf_lock:
            if self.recv_buf:
                tmp = self.recv_buf.pop(0)
                return tmp
            return None

    def handshake(self, client=True, syn_seg=None):
        while self.state != "ESTABLISHED":
            if client:
                if self.state == "CLOSED":
                    self._send(flags=['SYN'])
                    self.update_state("SYN_SENT")
                elif self.state == "SYN_SENT":  
                    tcp_seg = self._get_recv_buf()
                    while not tcp_seg:
                        tcp_seg = self._get_recv_buf()
                    if tcp_seg.flags == 18:
                        self._send(flags=['ACK'])
                        self.update_state("ESTABLISHED")
            else:
                if self.state == "CLOSED":
                    return
                elif self.state == "LISTEN":
                    tcp_seg = syn_seg
                    self.ack_num = self._get_next_seq(tcp_seg)

                    if tcp_seg.flags == 2:
                        self._send(flags=['SYN', 'ACK'])
                        self.update_state("SYN_RCVD")

                elif self.state == "SYN_RCVD":
                    tcp_seg = self._get_recv_buf()
                    while not tcp_seg:
                        tcp_seg = self._get_recv_buf()
                    if tcp_seg.flags == 16:
                        self.update_state("ESTABLISHED")
                        print(f"(Connection established with {self.dst_ip}:{self.dst_port})")
    
    def _handle_close(self, tcp_seg):
        if tcp_seg.flags == 1: # FIN
            self._send(flags=['ACK'])
            self.update_state("CLOSE_WAIT")
            time.sleep(2)
            self._send(flags=['FIN'])
        tcp_seg = self._get_recv_buf()
        while not tcp_seg:
            tcp_seg = self._get_recv_buf()

        if tcp_seg.flags == 16:
            self.update_state("CLOSED")
            self.terminate()

    def close(self):
        if self.state == "CLOSED":
            return
        self._send(flags=['FIN'])
        self.update_state("FIN_WAIT_1")
        tcp_seg = self._get_recv_buf()
        while not tcp_seg:
            tcp_seg = self._get_recv_buf()
        if tcp_seg.flags == 16:
            self.update_state("FIN_WAIT_2")
        tcp_seg = self._get_recv_buf()
        while not tcp_seg:
            tcp_seg = self._get_recv_buf()
        if tcp_seg.flags == 1:
            self._send(flags=['ACK'])
            self.update_state("TIME_WAIT")
            time.sleep(2)
            self.update_state("CLOSED")
        self.terminate()

        
        
    def send(self, data):
        time.sleep(0.01)
        max_size = self.mss - 20
        size = len(data)
        while len(data) > 0:
            if len(self.inflight_buf) < self.cwnd:
                self._send(flags=['ACK'], data=data[:max_size])
                data = data[max_size:]
            else:
                time.sleep(0.0001)
        print(f"(Sent data with size {size})")

        #self._send(flags=['ACK'], data=data)
    
    def recv(self, size):
        tcp_seg = self._get_recv_buf()
        while not tcp_seg:
            tcp_seg = self._get_recv_buf()
        if not tcp_seg:
            return None
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
        #print(f"    Received data with size {len(tcp_seg.data)}")
        if flags['FIN']:
            self._handle_close(tcp_seg)
        return tcp_seg.data
    