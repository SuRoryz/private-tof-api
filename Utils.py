import binascii

from scapy.all import *


class Utils:
    @staticmethod
    def i2h(nr):
        h = format(int(nr), 'x')
        line = '0' + h if len(h) % 2 else h

        n = 2
        return binascii.unhexlify(''.join([line[i:i+n] for i in range(0, len(line), n)]))
    
    @staticmethod
    def calc_plen(x):
        tcp_payload_len = len(x[TCP].payload)

        if x.haslayer(Padding):
            tcp_payload_len -= len(x[Padding])
        
        return tcp_payload_len