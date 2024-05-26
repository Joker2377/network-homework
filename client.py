import struct
import socket
from TCP_seg import TCP_seg, compute_checksum, verify_checksum
from Connection import Connection, TCPSocket
import random
import time
import threading


def worker():
    print("****NEW CLIENT CREATED****")
    src_port = random.randint(1000, 5000)
    client = TCPSocket(src_ip='127.0.0.2', dst_ip='127.0.0.1', src_port=src_port, dst_port=12345)
    client.bind(src_ip='127.0.0.2', src_port=src_port)
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
    client.close()

if __name__ == "__main__":

    n = 5
    threads = []
    for i in range(n):
        time.sleep(0.1)
        t = threading.Thread(target=worker)
        t.start()
        threads.append(t)
    count = 0
    for t in threads:
        t.join()
        count += 1
        print(f"Thread {count} Closed")
        
    