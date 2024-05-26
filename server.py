import struct
import socket
from Connection import Connection, TCPSocket
from TCP_seg import TCP_seg, compute_checksum, verify_checksum
import random
import threading
import time

threads = []

def new_connection(conn):
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
    print("Connection Closed")

def close_thread():
    while True:
        for t in threads:
            if not t.is_alive():
                t.join()
                threads.remove(t)
                print("1 Thread Closed")
        time.sleep(1)

if __name__ == "__main__":
    server = TCPSocket(src_ip='127.0.0.1', dst_ip='127.0.0.1', src_port=12345, dst_port=54321)
    server.bind(src_ip='127.0.0.1', src_port=12345)
    
    # create a thread closing empty thread
    t = threading.Thread(target=close_thread)
    t.start()
    while True:
        conn = server.accept()
        # create thread
        th = threading.Thread(target=new_connection, args=(conn,))
        th.start()
        threads.append(th)

