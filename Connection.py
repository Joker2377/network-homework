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
import random


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
            keys = list(self.connections.keys())
            try:
                for k in keys:
                    if self.connections[k].send_buf:
                        with self.connections[k].send_buf_lock:
                            if self.connections[k].send_buf:
                                tcp_seg, addr = self.connections[k].send_buf.pop(0)
                        tcp_seg.timer = time.time()
                        with self.connections[k].inflight_buf_lock:
                            self.connections[k].inflight_buf.append((tcp_seg.seq_num, tcp_seg))
                        tcp_seg = tcp_seg.pack(socket.inet_aton(self.connections[k].src_ip), socket.inet_aton(self.connections[k].dst_ip))
                        self.sock.sendto(tcp_seg, addr)
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
        if (addr[0], addr[1]) in self.connections.keys():
            return None

        print(f">{self.conn_num:<2}|     receive: ACK {tcp_seg.ack_num} SEQ {tcp_seg.seq_num} <<< {addr[0]}:{addr[1]}")
        print(f">{self.conn_num:<2}| (Connection from {addr[0]}:{addr[1]})")
        if flags['SYN']:
            conn_num = addr[1]
            conn = Connection(self.src_ip, addr[0], self.src_port, addr[1])
            self.connections[(addr[0], addr[1])] = conn
            conn.update_state("LISTEN")
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
        self.delayed_ack = False

        self.cwnd = 1
        self.threshold = 64
        self.mss = 1024

        self.rtt = 0.03
        self.rto = 1

        self.listening = True
        self.recv_buf_lock = threading.Lock()
        self.unhandled_buf_lock = threading.Lock()
        self.send_buf_lock = threading.Lock()
        self.send_data_buf_lock = threading.Lock()
        self.inflight_buf_lock = threading.Lock()
        self.delayed_ack_lock = threading.Lock()
        self.seq_num_lock = threading.Lock()
        self.send_next_lock = threading.Lock()
        self.waiting_for_ack_lock = threading.Lock()

        self.conn_num = 0
        self.first_mes = False
        self.waiting_for_ack = False
        self.send_next = False

        self.delay_ack_function = True
        self.constant_cwnd = False
        self.fast_retransmit_function = True

        self.last_received_seq = 0

        self.duplicate_ack = 0

        self.total_drop = 0

        self.start_threads()

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

    def check_timer(self):
        while self.listening:
            time.sleep(0.00001)
            if self.inflight_buf:
                with self.inflight_buf_lock:
                    copy = self.inflight_buf.copy()
                curr_time = time.time()
                late_list = [(curr_time - seg.timer, seg) for seq, seg in copy if (curr_time - seg.timer) > self.rto]
                for sample_rtt, seg in late_list:
                    if seg.timer == 0:
                        continue
                    
                    self.rtt = 0.875*self.rtt + 0.125*sample_rtt
                    devrtt = 0.75*self.rtt + 0.25*abs(sample_rtt - self.rtt)
                    self.rto = self.rtt + 4*devrtt
                    self.rto = max(1, self.rto)
                    self.rto = min(8, self.rto)
                    self.threshold = max(1, self.cwnd/2)
                    self.cwnd = 1
                    print(f"({self.conn_num})     Current RTO: {self.rto}")
                    print(f"({self.conn_num})     Timeout: ACK {seg.ack_num} SEQ {seg.seq_num}")
                    self._resend(seg)

    def _resend(self, tcp_seg):
        if not self.listening:
            return
        print(f"({self.conn_num})     Resending: ACK {tcp_seg.ack_num} SEQ {tcp_seg.seq_num}: {len(tcp_seg.data)} bytes")
        tcp_seg.timer = time.time()
        tcp_seg.ack_num = self.ack_num
        with self.inflight_buf_lock:
            self.inflight_buf.insert(0, (tcp_seg.seq_num, tcp_seg))
#        tcp_seg = tcp_seg.pack(socket.inet_aton(self.src_ip), socket.inet_aton(self.dst_ip))
        with self.send_buf_lock:
            self.send_buf.insert(0, (tcp_seg, (self.dst_ip, self.dst_port)))

    def _send_control(self):
        while self.listening:
            if self.send_next:
                with self.send_next_lock:
                    self.send_next = False
                if self.state != "ESTABLISHED":
                    self.cwnd = 1
                if len(self.inflight_buf) >= int(self.cwnd):
                    print(f"({self.conn_num})     |Inflight buffer full")
                while len(self.inflight_buf)<int(self.cwnd):
                    self._send(flags=['ACK'], nodata=False)
                    if not self.send_data_buf:
                        break
                    time.sleep(0.001)


    def _send(self, flags=[], nodata=True):
        if self.state != "ESTABLISHED":
            self.cwnd = 1
        if not self.listening:
            return

        if not nodata:
            with self.send_data_buf_lock:
                if self.send_data_buf:
                    data = self.send_data_buf.pop(0)
                else:
                    data = b''
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
        with self.seq_num_lock:
            self.seq_num = self._get_next_seq(tcp_seg)
        tcp_seg.timer = time.time()
        with self.inflight_buf_lock:
            self.inflight_buf.append((tcp_seg.seq_num, tcp_seg))
        
        if random.random() < 10e-6:
            # packet loss
            self.total_drop += 1
            print(f"({self.conn_num})     >>>>>>Packet loss: ACK {tcp_seg.ack_num} SEQ {tcp_seg.seq_num}<<<<<<")
            return
        
#        tcp_seg = tcp_seg.pack(socket.inet_aton(self.src_ip), socket.inet_aton(self.dst_ip))
        
        with self.send_buf_lock:
            self.send_buf.append((tcp_seg, (self.dst_ip, self.dst_port)))
    
    def start_threads(self):
        self.t = threading.Thread(target=self._recv, args=(1024,))
        self.t2 = threading.Thread(target=self.check_timer)
        self.t3 = threading.Thread(target=self._delay_ack)
        self.t4 = threading.Thread(target=self._send_control)
        self.t5 = threading.Thread(target=self._close_wait, daemon=True)
        self.t.start()
        self.t2.start()
        self.t3.start()
        self.t4.start()
        self.t5.start()

    def _close_wait(self):
        while self.state!="LAST_ACK" and self.listening:
            time.sleep(0.01)
            if self.state == "CLOSE_WAIT":
                time.sleep(0.01)
                self.update_state("LAST_ACK")
                self._send(flags=['FIN'])
                break

    def terminate(self):
        # terminate thread
        self.listening = False 
        print(f"({self.conn_num}) Dropped: {self.total_drop} packets")
        print(f"({self.conn_num}) Terminating connection with {self.dst_ip}:{self.dst_port}")
        if self.t and self.t.is_alive():
            self.t.join()
        if self.t2 and self.t2.is_alive():
            self.t2.join()
        if self.t3 and self.t3.is_alive():
            self.t3.join()
        if self.t4 and self.t4.is_alive():
            self.t4.join()
        if self.t5 and self.t5.is_alive():
            self.t5.join()

        print(f"({self.conn_num}) Connection with {self.dst_ip}:{self.dst_port} terminated")
    
    def append_unhandled(self, data):
        with self.unhandled_buf_lock:
            self.unhandled_buf.append(data)

    def _recvfrom(self):
        while not self.unhandled_buf:
            if not self.listening:
                return None, None
        with self.unhandled_buf_lock:
            if self.unhandled_buf:
                return self.unhandled_buf.pop(0)
            return None

    def _delay_ack(self):
        while self.listening:
            while not self.waiting_for_ack and self.listening:
                pass

            start_time = time.time()
            while self.waiting_for_ack:
                curr_time = time.time()

                #600 ms
                if curr_time - start_time > 0.6 and self.waiting_for_ack:
                    print(f"({self.conn_num})     |(Delayed ACK) SEND")
                    if self.delayed_ack:
                        with self.delayed_ack_lock:
                            self.delayed_ack = False
                    self._send(flags=['ACK'], nodata=False)
                    with self.waiting_for_ack_lock:                        
                        self.waiting_for_ack = False
                    break
                
            

    def _recv(self, size):
        while self.listening:
            data, addr = self._recvfrom()
            if not data:
                continue
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
            
            # list of flags raised
            

            if self.last_acked == tcp_seg.ack_num and self.fast_retransmit_function:
                self.duplicate_ack += 1
                with self.waiting_for_ack_lock:
                        self.waiting_for_ack = False
                with self.delayed_ack_lock:
                    self.delayed_ack = False
                print(f"({self.conn_num})     |{self.duplicate_ack} Duplicate ACK {self.duplicate_ack} SEQ {tcp_seg.seq_num}")
            
            self.last_acked = tcp_seg.ack_num # my seq  
            if self.inflight_buf:
                with self.inflight_buf_lock:
                    self.inflight_buf = [(seq, seg) for seq, seg in self.inflight_buf if seq >= self.last_acked] 
            if tcp_seg.seq_num == self.ack_num or self.ack_num ==0:
                self.ack_num = max(self.ack_num, self._get_next_seq(tcp_seg)) # their seq                

            if self.duplicate_ack >=3 and self.fast_retransmit_function:
                with self.waiting_for_ack_lock:
                    self.waiting_for_ack = False
                with self.delayed_ack_lock:
                    self.delayed_ack = False
                self.duplicate_ack = 0
                self.threshold = max(1, self.cwnd/2)
                self.cwnd = 1
                print(f"({self.conn_num})     |Expected SEQ {self.ack_num} but got SEQ {tcp_seg.seq_num}")
                if self.inflight_buf:
                    with self.inflight_buf_lock:
                        re_seg = [seg for seq, seg in self.inflight_buf if seq == tcp_seg.ack_num]
                    if re_seg:
                        re_seg[0].ack_num = self.ack_num
                        self._resend(re_seg[0])
                else:
                    self._send(flags=['ACK'], nodata=True)
                continue


            if self.state == "ESTABLISHED" and not self.constant_cwnd:
                if self.cwnd < self.threshold:
                    print(f"({self.conn_num})     >>>slow start mode<<<")
                else:
                    print(f"({self.conn_num})     >>>congestion avoidance mode<<<")
                self.cwnd = self.cwnd + 1 if self.cwnd < self.threshold else self.cwnd + 1/self.cwnd
                print(f"({self.conn_num})     |(cwnd: {self.cwnd*self.mss} MSS: {self.mss} threshold: {self.threshold})")
            else:
                self.cwnd = 1

            
            if self.state == "ESTABLISHED" and not flags['FIN'] and not flags['SYN'] and self.delay_ack_function:
                if not self.delayed_ack:
                    print(f"({self.conn_num})     |(Delayed ACK)")
                    with self.delayed_ack_lock:
                        self.delayed_ack = True
                    self.last_received_seq = max(tcp_seg.seq_num, self.last_received_seq)
                    if tcp_seg.seq_num == self.last_received_seq:
                        if tcp_seg not in self.recv_buf:
                            with self.recv_buf_lock:
                                self.recv_buf.append(tcp_seg)
                    with self.waiting_for_ack_lock:                                
                        self.waiting_for_ack = True
                    continue
                else:
                    with self.waiting_for_ack_lock:
                        self.waiting_for_ack = False
                    with self.delayed_ack_lock:
                        self.delayed_ack = False
                    
            else:
                if self.delayed_ack:
                    with self.waiting_for_ack_lock:
                        self.waiting_for_ack = False

            if self.state == "ESTABLISHED" and not flags['FIN'] and not flags['SYN']:
                if not self.constant_cwnd or self.send_data_buf:
                    with self.send_next_lock:
                        self.send_next = True
                else:
                    self._send(flags=['ACK'], nodata=False)

            elif flags['FIN'] and self.conn_num!=0:
                self._send(flags=['ACK'])
                self.update_state("CLOSE_WAIT")
                
            elif self.state == "LAST_ACK" and self.conn_num!=0:
                self.update_state("CLOSED")

            
            if not self.last_received_seq >= tcp_seg.seq_num:
                with self.recv_buf_lock:
                    self.recv_buf.append(tcp_seg)
                    self.last_received_seq = tcp_seg.seq_num
            else:
                print(f"({self.conn_num})     |Received duplicate SEQ {tcp_seg.seq_num}")

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
                        self._send(flags=['ACK'], nodata=True)
    

    def close(self):
        if self.state == "CLOSED":
            return
        print(f"BUFFER: {len(self.recv_buf)}")
        with self.recv_buf_lock:
            self.recv_buf = []
        print(f"Dropped: {self.total_drop}")
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
            self.listening = False
            time.sleep(2)
            self.update_state("CLOSED")
        self.terminate()

        
        
    def send(self, data):
        time.sleep(0.01)
        max_size = self.mss - 20
        size = len(data)
        while len(data) > 0:
            with self.send_data_buf_lock:
                self.send_data_buf.append(data[:max_size])                
            data = data[max_size:]
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
    