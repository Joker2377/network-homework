import struct
import socket
from Connection import Connection, TCPSocket
from TCP_seg import TCP_seg, compute_checksum, verify_checksum
import random
import threading
import time
import dns.resolver
import re
import hashlib
import argparse

threads = []

parser = argparse.ArgumentParser(description="TCP Server")
parser.add_argument('--port', type=int, help="Port Number", default=12345)

def compute_sha256sum(file_path):
    # Create a sha256 hash object
    hash_sha256 = hashlib.sha256()

    # Open the file in binary read mode
    with open(file_path, "rb") as f:
        # Read and update hash string value in blocks of 4K
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)

    # Return the hexadecimal digest of the hash
    return hash_sha256.hexdigest()

class Server:
    def __init__(self, conn):
        self.conn = conn
    
    def handle(self):
        while conn.state != 'CLOSED':
            data = self.conn.recv(1024)
            decoded = data.decode()
            if 'DNS_QUERY' in decoded:
                re_mes = re.search(r'DNS_QUERY<(.*)>DNS_END', decoded)
                if re_mes:
                    domain = re_mes.group(1)
                    self.dns_query_task(domain)
            elif 'CALCULATION' in decoded:
                re_mes = re.search(r'CALCULATION<(.*)>CALC_END', decoded)
                if re_mes:
                    expression = re_mes.group(1)
                    self.calculation_task(expression)
            elif 'FILE_TRANSFER' in decoded:
                re_mes = re.search(r'FILE_TRANSFER<(.*)>FILE_END', decoded)
                if re_mes:
                    filename = re_mes.group(1)
                    print(f"File Transfer for {filename}")
                    self.file_receive(filename)
            elif 'FILE_REQUEST' in decoded:
                re_mes = re.search(r'FILE_REQUEST<(.*)>FILE_END', decoded)
                if re_mes:
                    filename = re_mes.group(1)
                    print(f"File Request for {filename}")
                    self.file_transfer(filename)
        conn.terminate()

    @staticmethod
    def get_ip(domain):
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8']
        answer = resolver.resolve(domain, 'A') 
        return [ip.address for ip in answer]

    def dns_query_task(self, domain):
        print(f"(task) DNS Query for {domain}")
        # send back the ip address
        ip = self.get_ip(domain)[0]

        mes = b'DNS_QUERY<'+ip.encode()+b'>DNS_END'
        self.conn.send(mes)

    def calculation_task(self, expression):
        print(f"(task) Calculation for {expression}")
        # send back the result
        result = eval(expression)
        mes = b'CALCULATION<'+str(result).encode()+b'>CALC_END'
        self.conn.send(mes)

    def file_receive(self, filename):
        print(f"(task) File Receive for {filename}")
        # receive the file
        # just print out
        buf = b''
        while conn.state != 'CLOSED':
            data = self.conn.recv(1024)
            if data == b'FILE_END':
                break
            if data == b'FILE_BEGIN':
                continue
            buf += data
        # print out
        buf = buf.decode()
        print("File Received: ")
        print(f"{buf[:100]}...truncated")



    def file_transfer(self, filename):
        print(f"(task) File Transfer for {filename}")
        # send back the file
        mes = b'FILE_TRANSFER<'+filename.encode()+b'>FILE_END'
        self.conn.send(mes)
        mes = b'FILE_BEGIN'
        self.conn.send(mes)
        with open(filename, 'rb') as f:
            while True:
                data = f.read(65536)
                if not data:
                    break
                self.conn.send(data)
        mes = b'FILE_END'
        self.conn.send(mes)

def new_connection(conn):
    try:
        conn.delay_ack_function = False
        conn.handshake(client=False)
    except AttributeError:
        print("Connection Closed")
        return
    conn.send(b'')
    s = Server(conn)
    s.handle()
    while True and conn.state != "CLOSED":
        conn.recv(1024)


def close_thread():
    while True:
        for t in threads:
            if not t.is_alive():
                t.join()
                threads.remove(t)
                print("1 Thread Closed")
        time.sleep(1)

if __name__ == "__main__":
    src_port = parser.parse_args().port
    server = TCPSocket(src_ip='127.0.0.1', src_port=src_port)
    server.bind(src_ip='127.0.0.1', src_port=src_port)
    
    # create a thread closing empty thread
    t = threading.Thread(target=close_thread)
    t.start()
    while True:
        conn = server.accept()
        # create thread
        th = threading.Thread(target=new_connection, args=(conn,))
        th.start()
        threads.append(th)
        

