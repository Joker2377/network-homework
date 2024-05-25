import struct
import socket
from Connection import Connection, TCPSocket
from TCP_seg import TCP_seg, compute_checksum, verify_checksum
import random
import time


if __name__ == "__main__":
    server = TCPSocket(src_ip='127.0.0.1', dst_ip='127.0.0.1', src_port=12345, dst_port=54321)
    server.bind(src_ip='127.0.0.1', src_port=12345)
    conn = server.accept()
    conn.send(b'Hello World')
    conn.send(b'BEGIN')
    with open('./files/8192.txt', 'rb') as f:
        while True:
            data = f.read(65536)
            if not data:
                break
            conn.send(data)
    conn.send(b'END')
    while True and conn.state != "CLOSED":
        conn.recv(1024)
    conn.close()