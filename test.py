import struct
import socket
from TCP_seg import TCP_seg, compute_checksum, verify_checksum
from Connection import Connection, TCPSocket
import random
import time
import threading
import argparse
import re
import hashlib
import os

parser = argparse.ArgumentParser(description="TCP Server")
parser.add_argument('-i', '--ip', type=str, help="IP Address", default='127.0.0.1')
parser.add_argument('-p', '--port', type=int, help="Port Number", default=12345)
parser.add_argument('-d', '--dns', type=str, help="DNS Query", default='')
parser.add_argument('-c', '--cal', type=str, help="Calculation", default='')
parser.add_argument('-f', '--file', type=str, help="File Transfer", default='')

args = parser.parse_args()

def task1(conn):
    # dns query
    domain = args.dns
    mes = b'DNS_QUERY<'+domain.encode()+b'>DNS_END'
    conn.send(mes)
    while conn.state != 'CLOSED':
        data = conn.recv(1024)
        data = data.decode()
        if 'DNS_QUERY' in data:
            break
    
    # locate ip
    re_mes = re.search(r'DNS_QUERY<(.*)>DNS_END', data)

    print(f"(task1:  {re_mes.group(1)})")

def task2(conn):
    # calculation
    mes = b'CALCULATION<'+args.cal.encode()+b'>CALC_END'
    conn.send(mes)
    while conn.state != 'CLOSED':
        data = conn.recv(1024)
        data = data.decode()
        if 'CALCULATION' in data:
            break
    
    # locate result
    re_mes = re.search(r'CALCULATION<(.*)>CALC_END', data)

    print(f"(task2:  {re_mes.group(1)})")

def file_transfer(conn, filename):
    # file transfer
    mes = b'FILE_TRANSFER<'+filename.encode()+b'>FILE_END'
    conn.send(mes)
    mes = b'FILE_BEGIN'
    conn.send(mes)
    with open(filename, 'rb') as f:
        while True:
            data = f.read(65536)
            if not data:
                break
            conn.send(data)
    mes = b'FILE_END'
    conn.send(mes)

def task3(conn, filename):
    mes = b'FILE_REQUEST<'+filename.encode()+b'>FILE_END'
    conn.send(mes)
    buf = b''
    while conn.state != 'CLOSED':
        data = conn.recv(1024)
        if data == b'FILE_BEGIN':
            continue
        if data == b'FILE_END':
            break
        if b'FILE_TRANSFER' in data:
            continue
        buf += data
    buf = buf.decode()
    
    print(f"Received file:")
    print(f"{filename}: \n{buf}")


def worker():
    print("****NEW CLIENT CREATED****")
    src_port = random.randint(1000, 50000)
    client = TCPSocket(src_ip='127.0.0.2', src_port=src_port)
    client.bind(src_ip='127.0.0.2', src_port=src_port)
    conn = client.connect(dst_ip='127.0.0.1', dst_port=12345)
    conn.handshake()
    if args.dns:
        task1(conn)
    if args.cal:
        task2(conn)
    if args.file:
        task3(conn, args.file)

    conn.close()
    client.close()



if __name__ == "__main__":
    n = 2
    threads = []
    for i in range(n):
        time.sleep(0.1)
        t = threading.Thread(target=worker)
        t.start()
        threads.append(t)
    count = 0
    print(f"Number of Threads: {len(threads)}")
    for t in threads:
        t.join()
        count += 1
        print(f"Thread {count} Closed")
                       

                    
