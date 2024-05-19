import struct
import socket
from TCP import TCP
from TCP_seg import TCP_seg, compute_checksum, verify_checksum
import random
import time


if __name__ == "__main__":
    server = TCP(src_ip='127.0.0.1', dst_ip='127.0.0.1', src_port=12345, dst_port=54321)
    server.bind(src_ip='127.0.0.1', src_port=12345)
    server.recv(size=1024)
