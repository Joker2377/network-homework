import struct
import socket
from TCP_seg import TCP_seg, compute_checksum, verify_checksum
from Connection import Connection, TCPSocket
import random
import time


if __name__ == "__main__":
    client = TCPSocket(src_ip='127.0.0.1', dst_ip='127.0.0.1', src_port=54321, dst_port=12345)
    client.bind(src_ip='127.0.0.1', src_port=54321)
    conn = client.connect(dst_ip='127.0.0.1', dst_port=12345)
    data = conn.recv(1024)
    print(data)
    conn.close()
        
    


        
        
    