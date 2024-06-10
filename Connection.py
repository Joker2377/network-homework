import struct
import socket
from TCP_seg import TCP_seg, compute_checksum, verify_checksum
import random
import time
import datetime
import builtins
import threading
import sys
import time


class TCPSocket:
    def __init__(self, src_ip, dst_ip='0.0.0.0', src_port=0, dst_port=0):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(5)
        self.sock_recv_lock = threading.Lock()

        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.seq_num = 0
        self.ack_num = 0

        self.recv_buf = b''
        self.state = "CLOSED"
        self.connections = {}
        self.conn_to_num = {}
        self.conn_num = 1

        self.glob_recv_buf = []
        self.glob_recv_buf_lock = threading.Lock()
        self.listening = True
        self.sending = True


        self.conn_rec = 0

        
    
        self.start_threads()

    def print_seg(self, tcp_seg):
        print("*"*10)
        print(f">{self.conn_num:<2}|     src_port: {tcp_seg.src_port}")
        print(f">{self.conn_num:<2}|     dst_port: {tcp_seg.dst_port}")
        print(f">{self.conn_num:<2}|     seq_num: {tcp_seg.seq_num}")
        print(f">{self.conn_num:<2}|     ack_num: {tcp_seg.ack_num}")
        print(f">{self.conn_num:<2}|     data_offset: {tcp_seg.data_offset}")
        print(f">{self.conn_num:<2}|     reserved: {tcp_seg.reserved}")
        print(f">{self.conn_num:<2}|     flags: {tcp_seg.flags}")
        print(f">{self.conn_num:<2}|     window_size: {tcp_seg.window_size}")
        print(f">{self.conn_num:<2}|     checksum: {tcp_seg.checksum}")
        print(f">{self.conn_num:<2}|     urgent_pointer: {tcp_seg.urgent_pointer}")
        print(f">{self.conn_num:<2}|     options: {tcp_seg.options}")
        print(f">{self.conn_num:<2}|     data: {tcp_seg.data[:10]}...truncated")
        print("*"*10)

    def update_state(self, new_state):
        self.state = new_state
        print(f">{self.conn_num:<2}| Server State: {self.state}")

    def start_threads(self):
        self.t_recv = threading.Thread(target=self._recv)
        self.t_recv2 = threading.Thread(target=self._recv2)
        self.t_send = threading.Thread(target=self._send)
        self.t_remove = threading.Thread(target=self._remove_closed_connections)

        self.t_recv.start()
        self.t_recv2.start()
        self.t_send.start()
        self.t_remove.start()

    def _remove_closed_connections(self):
        while self.listening:
            if not self.connections:
                time.sleep(1)
                continue
            keystodelete = []
            keys = list(self.connections.keys())
            for k in keys:
                if self.connections[k].state == "CLOSED":
                    keystodelete.append(k)
            [self.connections.pop(k) for k in keystodelete]

    def _send(self):
        while self.sending:
            time.sleep(0.01)
            keys = list(self.connections.keys())
            try:
                for k in keys:
                    if self.connections[k].send_buf:
                        with self.connections[k].send_buf_lock:
                            while self.connections[k].send_buf:
                                data, addr = self.connections[k].send_buf.pop(0)
                                self.sock.sendto(data, addr)
                                time.sleep(0.001)
            except KeyError:
                pass

    def _recv2(self):
        while self.listening:
            try:
                with self.sock_recv_lock:
                    data, addr = self.sock.recvfrom(1024)
            except socket.timeout:
                continue
            except socket.error:
                break
            not_conn = True
            try:
                conn = self.connections[(addr[0], addr[1])]
                not_conn = False
                conn.append_unhandled((data, addr))
            except KeyError:
                pass
            if not_conn:
                print(f">{self.conn_num:<2}| ****RECEIVED CONNECTION FROM {addr[0]}:{addr[1]}****")
                self.conn_rec += 1
                with self.glob_recv_buf_lock:
                    self.glob_recv_buf.append((data, addr))

    def _recv(self):
        while self.listening:
            try:
                with self.sock_recv_lock:
                    data, addr = self.sock.recvfrom(1024)
            except socket.timeout:
                continue
            except socket.error:
                break
            not_conn = True
            try:
                conn = self.connections[(addr[0], addr[1])]
                not_conn = False
                conn.append_unhandled((data, addr))
            except KeyError:
                pass
            if not_conn:
                print(f">{self.conn_num:<2}| ****RECEIVED CONNECTION FROM {addr[0]}:{addr[1]}****")
                self.conn_rec += 1
                with self.glob_recv_buf_lock:
                    self.glob_recv_buf.append((data, addr))

    def _get_glob_recv_buf(self): # connectionless
        while not self.glob_recv_buf:
            time.sleep(0.1) # make sure it wont cause starvation
        if self.glob_recv_buf:
            with self.glob_recv_buf_lock:
                if self.glob_recv_buf:
                    return self.glob_recv_buf.pop(0)
                return None

    def bind(self, src_ip, src_port):
        self.src_ip = src_ip
        self.src_port = src_port
        self.sock.bind((src_ip, src_port))
        self.update_state("LISTEN")
        print(f">{self.conn_num:<2}| Server is listening on {src_ip}:{src_port}")
    
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
            print(f">{self.conn_num:<2}| Expected checksum: {compute_checksum(tcp_seg.pack(socket.inet_aton(self.src_ip), socket.inet_aton(addr[0])))}")
            print(f">{self.conn_num:<2}| Received checksum: {tcp_seg.checksum}")
            self.print_seg(tcp_seg)
            return None
        
        print(f">{self.conn_num:<2}|     receive: ACK {tcp_seg.ack_num} SEQ {tcp_seg.seq_num} <<< {addr[0]}:{addr[1]}")
        print(f">{self.conn_num:<2}| (Connection from {addr[0]}:{addr[1]})")
        if flags['SYN']:
            conn_num = addr[1]
            conn = Connection(self.src_ip, addr[0], self.src_port, addr[1])
            
            conn.update_state("LISTEN")
            self.connections[(addr[0], addr[1])] = conn
            self.conn_to_num[(addr[0], addr[1])] = self.conn_num
            conn.assign_conn_num(self.conn_num)
            self.conn_num += 1
            
            conn.syn_seg = tcp_seg
            
            return conn

    def connect(self, dst_ip, dst_port):
        conn = Connection(self.src_ip, dst_ip, self.src_port, dst_port)
        self.connections[(dst_ip, dst_port)] = conn
        self.conn_to_num[(dst_ip, dst_port)] = self.conn_num
        return conn

    def close(self):
        self.sending = False
        self.listening = False
        keys = list(self.connections.keys())
        for k in keys:
            self.connections[k].close()

        time.sleep(1) # wait for socket to complete
        self.sock.close()
        if self.t_recv.is_alive():
            self.t_recv.join()
        if self.t_send.is_alive():
            self.t_send.join()
        if self.t_remove.is_alive():
            self.t_remove.join()
        if self.t_recv2.is_alive():
            self.t_recv2.join()
        
        print("Socket closed")
        sys.exit(0)

class Connection:
    def __init__(self, src_ip, dst_ip, src_port, dst_port):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.seq_num = 0
        self.ack_num = 0

        self.last_acked = 0

        self.syn_seg = None

        self.state = "CLOSED"

        self.inflight_buf = []
        self.recv_buf = []
        self.unhandled_buf = []
        self.send_buf = []
        self.send_data_buf = []

        self.cwnd = 1
        self.threshold = 64
        self.mss = 1024

        self.listening = True
        self.recv_buf_lock = threading.Lock()
        self.unhandled_buf_lock = threading.Lock()
        self.send_buf_lock = threading.Lock()
        self.send_data_buf_lock = threading.Lock()

        self.conn_num = 0
        self.first_mes = False
    

        self.start_recv_thread()

    def assign_conn_num(self, num):
        self.conn_num = num

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

    def print_seg(self, tcp_seg):
        print("*"*10)
        print(f"({self.conn_num})     src_port: {tcp_seg.src_port}")
        print(f"({self.conn_num})     dst_port: {tcp_seg.dst_port}")
        print(f"({self.conn_num})     seq_num: {tcp_seg.seq_num}")
        print(f"({self.conn_num})     ack_num: {tcp_seg.ack_num}")
        print(f"({self.conn_num})     data_offset: {tcp_seg.data_offset}")
        print(f"({self.conn_num})     reserved: {tcp_seg.reserved}")
        print(f"({self.conn_num})     flags: {tcp_seg.flags}")
        print(f"({self.conn_num})     window_size: {tcp_seg.window_size}")
        print(f"({self.conn_num})     checksum: {tcp_seg.checksum}")
        print(f"({self.conn_num})     urgent_pointer: {tcp_seg.urgent_pointer}")
        print(f"({self.conn_num})     options: {tcp_seg.options}")
        print(f"({self.conn_num})     data: {tcp_seg.data[:10]}...truncated")
        print("*"*10)
    
    def update_state(self, new_state):
        self.state = new_state
        print(f"({self.conn_num}) ({self.state})")

    def _send(self, flags=[]):
        with self.send_data_buf_lock:
            if self.send_data_buf:
                data = self.send_data_buf.pop(0)
            else:
                data = b''

        if self.seq_num == 0:
            self.seq_num = random.randint(0, 10000)
        print(f"({self.conn_num}) sent: ", end="")
        print(*flags, sep=", ", end=" : ")
        print(f"({self.conn_num}) ACK {self.ack_num} SEQ {self.seq_num}: {len(data)} bytes")
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
        self.listening = False 
        print(f"({self.conn_num}) Terminating connection with {self.dst_ip}:{self.dst_port}")
        if self.t and self.t.is_alive():
            self.t.join()
        print(f"({self.conn_num}) Connection with {self.dst_ip}:{self.dst_port} terminated")
    
    def append_unhandled(self, data):
        with self.unhandled_buf_lock:
            self.unhandled_trigger = True
            self.unhandled_buf.append(data)

    def _recvfrom(self):
        while not self.unhandled_buf:
            time.sleep(0.01)
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
                print(f"({self.conn_num})     Checksum failed")
                print(f"({self.conn_num})     Expected checksum: {compute_checksum(tcp_seg.pack(socket.inet_aton(self.src_ip), socket.inet_aton(self.dst_ip)))}")
                print(f"({self.conn_num})     Received checksum: {tcp_seg.checksum}")
                # show two segments comparison table (left, right)
                print(f"({self.conn_num})     Seq_num: {tcp_seg.seq_num} == {self.ack_num}")
                print(f"({self.conn_num})     Ack_num: {tcp_seg.ack_num} == {self.seq_num}")
                print()
                self.print_seg(tcp_seg)
                continue
            
            if tcp_seg.seq_num > self.ack_num and self.ack_num!=0:
                print(f"({self.conn_num})     Expected SEQ {self.ack_num} but got SEQ {tcp_seg.seq_num}")
                continue

            self.ack_num = max(self.ack_num, self._get_next_seq(tcp_seg)) # their seq
            self.last_acked = tcp_seg.ack_num # my seq

            if self.inflight_buf:
                self.inflight_buf = [(seq, seg) for seq, seg in self.inflight_buf if seq >= self.last_acked]
            
            #self.cwnd = self.cwnd + 1 if self.cwnd < self.threshold else self.cwnd + 1/self.cwnd
            
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
            print(f"({self.conn_num}) receive: ", end="")
            print(*flags, sep=", ", end=" : ")
            print(f"({self.conn_num}) ACK {tcp_seg.ack_num} SEQ {tcp_seg.seq_num}: {len(tcp_seg.data)} bytes")
            #print(f"({self.conn_num}) (cwnd: {self.cwnd*self.mss} MSS: {self.mss} threshold: {self.threshold})")
            # don't ack fin, syn
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
            if self.state == "ESTABLISHED" and not flags['FIN'] and not flags['SYN']:
                self._send(flags=['ACK'])
            elif flags['FIN'] and self.conn_num!=0:
                self.update_state("CLOSE_WAIT")
                self.update_state("LAST_ACK")
                self._send(flags=['FIN'])
            elif self.state == "LAST_ACK" and self.conn_num!=0:
                self.update_state("CLOSED")

            with self.recv_buf_lock:
                self.recv_buf.append(tcp_seg)
            #print(f"({self.conn_num})     buf: {len(self.recv_buf)}")

    def _get_recv_buf(self):
        # pop the front
        while not self.recv_buf:
            time.sleep(0.01)
            
        with self.recv_buf_lock:
            #print(f"({self.conn_num})     buf: {len(self.recv_buf)}")
            tmp = self.recv_buf.pop(0)
            if not tmp:
                return None
            return tmp


    def handshake(self, client=True):
        while self.state != "ESTABLISHED":
            time.sleep(0.01)
            if client:
                if self.state == "CLOSED":
                    self._send(flags=['SYN'])
                    self.update_state("SYN_SENT")
                elif self.state == "SYN_SENT":  
                    tcp_seg = self._get_recv_buf()            
                    if tcp_seg.flags == 18:
                        self._send(flags=['ACK'])
                        self.update_state("ESTABLISHED")
            else:
                if self.state == "CLOSED":
                    return
                elif self.state == "LISTEN":
                    tcp_seg = self.syn_seg
                    self.ack_num = self._get_next_seq(tcp_seg)

                    if tcp_seg.flags == 2:
                        self._send(flags=['SYN', 'ACK'])
                        self.update_state("SYN_RCVD")

                elif self.state == "SYN_RCVD":
                    tcp_seg = self._get_recv_buf()
                    if tcp_seg.flags == 16:
                        self.update_state("ESTABLISHED")
                        print(f"({self.conn_num}) (Connection established with {self.dst_ip}:{self.dst_port})")
    

    def close(self):
        if self.state == "CLOSED":
            return
        with self.recv_buf_lock:
            self.recv_buf = []
        self._send(flags=['FIN'])
        self.update_state("FIN_WAIT_1")
        tcp_seg = self._get_recv_buf()

        if tcp_seg.flags == 16:
            self.update_state("FIN_WAIT_2")
        tcp_seg = self._get_recv_buf()
        while tcp_seg.flags != 1:
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
            if len(self.inflight_buf) <= self.cwnd:
                with self.send_data_buf_lock:
                    self.send_data_buf.append(data[:max_size])
                if not self.first_mes:
                    self._send(flags=['ACK'])
                    self.first_mes = True   
                
                data = data[max_size:]
            else:
                time.sleep(0.001)
        #print(f"({self.conn_num}) (Sent data with size {size})")

        #self._send(flags=['ACK'], data=data)
    
    def recv(self, size):
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
        #print(f"({self.conn_num})     Received data with size {len(tcp_seg.data)}")
        """if flags['FIN']:
            self._handle_close(tcp_seg)"""
        return tcp_seg.data
    