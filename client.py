import struct
import socket
from TCP_seg import TCP_seg, compute_checksum, verify_checksum
from Connection import Connection, TCPSocket
import random
import time


if __name__ == "__main__":
    src_port = random.randint(1000, 5000)
    client = TCPSocket(src_ip='127.0.0.1', dst_ip='127.0.0.1', src_port=src_port, dst_port=12345)
    client.bind(src_ip='127.0.0.1', src_port=src_port)
    conn = client.connect(dst_ip='127.0.0.1', dst_port=12345)
    while True:
        data = conn.recv(1024)
        if data == b'BEGIN':
            break
        print(data)
    filename = f"./test{random.randint(0, 1000)}.txt"
    with open(filename, 'wb') as f:
        while True:
            data = conn.recv(1024)
            if not data:
                continue
            if data == b'END':
                break
            f.write(data)
    conn.close()
        
    


        
        
    