import struct
import socket
from TCP_seg import TCP_seg, compute_checksum, verify_checksum
from TCP import TCP
import random
import time


if __name__ == "__main__":
    client = TCP(src_ip='127.0.0.1', dst_ip='127.0.0.1', src_port=54321, dst_port=12345)
    client.bind(src_ip='127.0.0.1', src_port=54321)
    client.connect(dst_ip='127.0.0.1', dst_port=12345)

    data = client.recv(size=1024)

    
    client.send(data=b'Hello, Server!')
    received_data = client.recv(size=1024)
    print(f"Received Data: {received_data}")
    
    client.close()

    
        
    


        
        
    