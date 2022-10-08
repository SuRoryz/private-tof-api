from pickletools import read_uint1
import random
import time
import binascii
import os
import sys
import regex
import json
import socket
import asyncio
import websockets
import secrets

from Config import SERVER_IP, SERVER_PORT, YOUR_LOCAL_IP, LOGIN_PAYLOAD
from scapy.all import *
from threading import Thread
from Utils import Utils

SERVER_MAC = None
while not(SERVER_MAC):
    SERVER_MAC = getmacbyip(SERVER_IP)

class GameConnection(Thread):
    def __init__(self, OutputStreamer):
        Thread.__init__(self)
        self.countdown = 2
        self.stop = 0
        self.myseq = 0
        self.myack = 0

        self.DST_HOST = SERVER_IP
        self.DST_PORT = SERVER_PORT
        self.SRC_HOST= YOUR_LOCAL_IP
        self.SRC_PORT = random.randint(50000,65000)

        self.ip = Ether(dst=SERVER_MAC)/IP(src=self.SRC_HOST, dst=self.DST_HOST, flags="DF", ttl=128)
        self.logged = False

        self.OutputStreamer = OutputStreamer

    def send_login_data(self, x):
        tcp_payload_len = Utils.calc_plen(x)

        load = LOGIN_PAYLOAD
        load = bytearray.fromhex(load)

        PA = TCP(sport=self.SRC_PORT, dport=self.DST_PORT, flags='PA', window=515, seq=x[TCP].ack+4, ack=x[TCP].seq + tcp_payload_len)/Raw(load=load)
        sendp(self.ip/PA, verbose=False)

        self.myack = x[TCP].seq + tcp_payload_len
        self.myseq = x[TCP].ack
        
        self.logged = True
        self.countdown = 2
    
    def connect(self):
        SYN = TCP(sport=self.SRC_PORT, dport=self.DST_PORT, flags='S', seq=1000, window=64240, options=[('MSS', 1460), ('NOP', None), ('WScale', 8), ('NOP', None), ('NOP', None), ('SAckOK', b'')])
        SYNACK = srp1(self.ip/SYN, verbose=False)

        ACK = TCP(sport=self.SRC_PORT, dport=self.DST_PORT, flags='A', seq=SYNACK.ack, ack=SYNACK.seq+1, window=517)
        pa = sendp(self.ip/ACK, verbose=False)

        PA = TCP(sport=self.SRC_PORT, dport=self.DST_PORT, flags='PA', window=515, seq=SYNACK.ack, ack=SYNACK.seq + 1)/Raw(load="\x7c\x02\x00\x00")
        sendp(self.ip/PA, verbose=False)

    def pkt_callback(self, x):
        is_fin = False

        if x.haslayer(TCP):
            if x[TCP].flags & 0x01:
                if x[TCP].dport != self.SRC_PORT:
                    tcp_payload_len = Utils.calc_plen(x)

                    myack = x[TCP].seq + tcp_payload_len
                    
                    ip = Ether(dst=SERVER_MAC)/IP(src=self.SRC_HOST, dst=self.DST_HOST, flags="DF", ttl=128)
                    ACK = TCP(sport=x[TCP].dport, dport=self.DST_PORT, flags='FA', seq=x[TCP].ack, ack=myack, window=514)
                    sendp(ip/ACK, verbose=False)

                    return
                else:
                    is_fin = True
        else:
            return

        pkt_payload = bytes(x[TCP].payload)

        if b"127.0.0.1" in pkt_payload:
            self.send_login_data(x)
            return

        if b"AvatarFrame" in pkt_payload and b"\xa9\x06\x00\x00" in pkt_payload:
            self.OutputStreamer.CHAT_OUT_QUEUE.append(pkt_payload)

        if self.logged:
            if self.countdown:
                self.countdown -= 1
                return
            
            if is_fin:
                flags = 'FA'
                self.stop = True
            else:
                flags = 'A'
                
            tcp_payload_len = Utils.calc_plen(x)

            self.myack = x[TCP].seq + tcp_payload_len
            self.myseq = x[TCP].ack

            ACK = TCP(sport=self.SRC_PORT, dport=self.DST_PORT, flags=flags, seq=self.myseq, ack=self.myack, window=514)
            sendp(self.ip/ACK, verbose=False)
        
        if self.stop:
            self.countdown = 2
            self.stop = 0
            self.myseq = 0
            self.myack = 0

            self.SRC_PORT = random.randint(50000,65000)
            self.ip = Ether(dst=SERVER_MAC)/IP(src=self.SRC_HOST, dst=self.DST_HOST, flags="DF", ttl=128)
            self.logged = False

            self.connect()
            
    def run(self):
        self.connect()
        sniff(prn=self.pkt_callback, filter="tcp src port 30031", store=0)

