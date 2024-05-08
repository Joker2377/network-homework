import struct

def _getChecksum(**kwargs):
    # pseudo header
    # source address, destination address, fixed 8 bits, protocol=6, TCP length
    """
    # !: network byte order
    # 4s: 4 bytes string (4)
    # B: unsigned char (1)
    # H: unsigned short (2)
    # total 12 bytes
    """
    pseudo_header = struct.pack('!4s4sBBH', kwargs['src_ip'], kwargs['dst_ip'],0 ,6, kwargs['tcp_len'])
    tcp_header = struct.pack('!HHLLBBHHH', kwargs['src_port'], kwargs['dst_port'], kwargs['seq_num'], kwargs['ack_num'], kwargs['data_offset'], kwargs['reserved'], kwargs['flags'], kwargs['window_size'], kwargs['urgent_pointer'])
    tcp_data = kwargs['data']

    # calculate checksum
    chksum = 0
    pass

class TCP_seg:
    def __init__(self, src_port, dst_port, seq_num, ack_num, data_offset, flags, window_size, checksum, urgent_pointer, data):
        self.src_port = src_port #16
        self.dst_port = dst_port #16
        self.seq_num = seq_num #32
        self.ack_num = ack_num #32
        self.data_offset = 4 #4 (length)
        self.reserved = b'0000' # 4
        self.flags = flags #8
        self.window_size = window_size #16
        self.checksum = b'0000000000000000' #16
        self.urgent_pointer = urgent_pointer #16
        # suppose there's no options
        self.data = data

    def _getlen(self):
        tmp = struct.pack('!HHLLBBHHH', self.src_port, self.dst_port, self.seq_num, self.ack_num, self.data_offset, self.reserved, self.flags, self.window_size, self.checksum, self.urgent_pointer)
        return len(tmp) + len(self.data)

    def _set_data_offset(self):
        self.data_offset = 4

    def _setchecksum(self, checksum):
        self.checksum = checksum
    
        
        
        
    