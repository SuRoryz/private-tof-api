from scapy.all import *
import random
import time
from threading import Thread
#import pydivert
import binascii
import os
import sys
import regex
import json
import socket
import asyncio
import websockets
import secrets

skip = 2
stop = 0
myseq = 0
myack = 0

CONNECTIONS = set()

LOGIN_PAYLOAD = "1000000000000a000c000400000008000a00000056040000600200003800000034006000040008000c001000140018001c002000240028002c003000340038003c0040000000440048004c005000540058005c00340000005c000000680000008000000004000000a8000000ac000000b4000000b8000000bc000000c4000000c8000000cc000000d0000000f800000000800000020000003001000034010000380100003c01000044010000480100004c0100000b000000312e31352e30372e31313800140000003135323336333838303534303935303833363635000000002800000063356362633663376536666262366633323932376466633365323636303565386638633563396531000000000000000000000000050000003239303933000000000000000000000003000000313133000500000072752d52550000000000000000000000000000000000000000000000000000002700000053797374656d206d616e7566616374757265722d53797374656d2050726f64756374204e616d65003e0000006437393934343965353136663639636164623930613936373166643363333934353336613237346534613464363563643439303136363833323231633530000002000000656e000001000000300000000100000037000000070000004765744970763600000000000000000000000000000000007a000000546f7765726f6646616e746173795f546f7765726f6646616e746173792d57696e646f77732d616e64726f69642d57696e646f77732d546f7765726f6646616e746173792d61306361373932313636386637643138633039366164383530313135383966642d31353233363338383035343039353038333636350000" # Сюда своё содержимое
YOUR_LOCAL_IP = "62.109.15.182" # Замени на свой
SERVER_MAC = None

while not(SERVER_MAC):
    SERVER_MAC = getmacbyip("43.159.30.254")

NOPRINT_TRANS_TABLE = {
    i: None for i in range(0, sys.maxunicode + 1) if not chr(i).isprintable()
}

def i2h(nr):
    h = format(int(nr), 'x')
    line = '0' + h if len(h) % 2 else h

    n = 2
    return binascii.unhexlify(''.join([line[i:i+n] for i in range(0, len(line), n)]))

class Sniffer(Thread):
    def __init__(self, writer):
        Thread.__init__(self)
        self.skip = 2
        self.stop = 0
        self.myseq = 0
        self.myack = 0
        
        self.writer = writer

        self.dst_host = "43.159.30.254"
        self.dst_port = 30031

        self.src_host= YOUR_LOCAL_IP
        self.src_port = random.randint(50000,65000)

        self.ip = Ether(dst=SERVER_MAC)/IP(src=self.src_host, dst=self.dst_host, flags="DF", ttl=128)

        self.connected = False

    def pkt_callback(self, x):
        
        # Проверка на FIN для соединений не на текущем порте и отвправка ответа
        if TCP in x:
            if x[TCP].dport != self.src_port:
                if x[TCP].flags & 0x01:
                    tcp_payload_len = len(x[TCP].payload)
                    if x.haslayer(Padding):
                        tcp_payload_len -= len(x[Padding])

                    myack = x.getlayer("TCP").seq+tcp_payload_len
                    
                    ip = Ether(dst=SERVER_MAC)/IP(src=self.src_host, dst=self.dst_host, flags="DF", ttl=128)
                    ACK = TCP(sport=x[TCP].dport, dport=self.dst_port, flags='FA', seq=x.getlayer("TCP").ack, ack=myack, window=514)
                    sendp(ip/ACK, verbose=False)
                return
        else:
            return

        # Проверка на FIN для соединений на текущем порте
        F = False

        if x.haslayer(TCP):
            if x[TCP].flags & 0x01:
                F = True

        # Данные пакета
        pl = bytes(x[TCP].payload)

        # Проверка на сообщение из глобала в пакете
        if b"AvatarFrame" in pl and b"\xa9\x06\x00\x00" in pl:
            self.writer.queue.append(pl)
        
        if b"#DER#" in pl:
            pass
            #self.writer.api.append(['get_id', pl])

        # Проверка на логин
        if b"127.0.0.1" in pl:
            tcp_payload_len = len(x[TCP].payload)

            load = LOGIN_PAYLOAD
            load = bytearray.fromhex(load)
            PA = TCP(sport=self.src_port, dport=self.dst_port, flags='PA', window=515, seq=x.getlayer("TCP").ack+4, ack=x.getlayer("TCP").seq + tcp_payload_len)/Raw(load=load)
            sendp(self.ip/PA, verbose=False)

            self.myack = x.getlayer("TCP").seq+tcp_payload_len
            self.myseq = x.getlayer("TCP").ack
            
            self.connected = True
            self.skip = 2
            return

        elif self.connected:

            if self.skip:
                self.skip -= 1
                return
            
            if x.haslayer(TCP):
                if F:
                    flags = 'FA'
                    self.stop = 1
                else:
                    flags = 'A'
                    
                tcp_payload_len = len(x[TCP].payload)
                if x.haslayer(Padding):
                    tcp_payload_len -= len(x[Padding])

                self.myack = x.getlayer("TCP").seq+tcp_payload_len
                self.myseq = x.getlayer("TCP").ack

                ACK = TCP(sport=self.src_port, dport=self.dst_port, flags=flags, seq=self.myseq, ack=self.myack, window=514)
                sendp(self.ip/ACK, verbose=False)

                if b"Neko" in pl:
                    self.send_message("response", "Pingpow") 
            
            if self.stop:
                    self.skip = 2
                    self.stop = 0
                    self.myseq = 0
                    self.myack = 0

                    self.dst_host = "43.159.30.254"
                    self.dst_port = 30031

                    self.src_host= YOUR_LOCAL_IP
                    self.src_port = random.randint(50000,65000)

                    self.ip = Ether(dst=SERVER_MAC)/IP(src=self.src_host, dst=self.dst_host, flags="DF", ttl=128)

                    self.connected = False

                    self.connect()
    
    def connect(self):
        SYN = TCP(sport=self.src_port, dport=self.dst_port, flags='S', seq=1000, window=64240, options=[('MSS', 1460), ('NOP', None), ('WScale', 8), ('NOP', None), ('NOP', None), ('SAckOK', b'')])
        SYNACK = srp1(self.ip/SYN, verbose=False)

        ACK = TCP(sport=self.src_port, dport=self.dst_port, flags='A', seq=SYNACK.ack, ack=SYNACK.seq+1, window=517)
        pa = sendp(self.ip/ACK, verbose=False)

        PA = TCP(sport=self.src_port, dport=self.dst_port, flags='PA', window=515, seq=SYNACK.ack, ack=SYNACK.seq + 1)/Raw(load="\x7c\x02\x00\x00")
        sendp(self.ip/PA, verbose=False)
    
    def api_get_info(self, query, *args, **kwargs):
        pid = str(query)

        lx = b'\x80\x00\x00\x00'
        PA = TCP(sport=self.src_port, dport=self.dst_port, flags='PA', window=512, seq=self.myseq, ack=self.myack)/Raw(load=lx)
        srp1(self.ip/PA, verbose=False, timeout=1)

        lx = "1000000000000a000c000400000008000a0000007004000064000000100000000c0010000400080000000c000c0000000a0000003f010000440000001400000000000e0014000400080000000c0010000e0000001800000061ae0a00080000001200000000000000000000000e00000035353937323031333830333739390000"
        lx = bytearray.fromhex(lx)

        lx = lx.replace(b"55972013803799", pid.encode("UTF_8"))

        PA = self.ip/TCP(sport=self.src_port, dport=self.dst_port, flags='PA', reserved=0, window=4149, seq=self.myseq, ack=self.myack)/Raw(load=lx)
        PA[TCP].window = 512
        PA[TCP].dataofs = 5

        del PA[IP].ihl
        del PA[TCP].chksum
        del PA[IP].chksum

        PA.show2()
        sendp(PA)
        
        total = []

        def sr(x):
            if len(x[TCP].payload) > 400 and not(b"\xa9\x06\x00\x00" in bytes(x[TCP].payload)) and not(b"127.0.0.1" in bytes(x[TCP].payload)):
                total.append(bytes(x[TCP].payload))
            if b"NameReportID" in bytes(x[TCP].payload):
                return True

        t = AsyncSniffer(filter="tcp src port 30031", count=25, timeout=5, stop_filter=sr)
        t.start()
        t.join()

        total = b''.join(total)
        
        self.writer.api.append(['get_info', [total, pid]])


    def api_get_id(self, query, *args, **kwargs):
        player = query

        lx = b'\xd4\x00\x00\x00'
        PA = TCP(sport=self.src_port, dport=self.dst_port, flags='PA', window=512, seq=self.myseq, ack=self.myack)/Raw(load=lx)
        srp1(self.ip/PA, verbose=False, timeout=1)

        lx = "1000000000000a000c000400000008000a00000070040000b8000000100000000c0010000400080000000c000c0000000a00000039010000980000002400000000001e003000040008000c001000140018001c00000020000000240028002c001e0000005c00000061ae0a00400000002e020000240000001b0000005a000000100000009e0d00000a000000e803000000000000000000000f000000494d46494e455448414e4b53414c4c000f00000044756d6d79417574685469636b6574000e00000035353937323031333836373530360000"

        lx = bytearray.fromhex(lx)

        player = player.encode("UTF_8")
        player_nulls = "\x00" * (15 - len(player))
        player = (player.decode("UTF_8") + player_nulls).encode("UTF_8")

        lx = lx.replace(b"IMFINETHANKSALL", player)

        PA = self.ip/TCP(sport=self.src_port, dport=self.dst_port, flags='PA', reserved=0, window=4149, seq=self.myseq, ack=self.myack)/Raw(load=lx)
        PA[TCP].window = 512
        PA[TCP].dataofs = 5

        del PA[IP].ihl
        del PA[TCP].chksum
        del PA[IP].chksum

        PA.show2()
        sendp(PA)

        res = []

        def sn(x):
            if b"#DER#" in bytes(x[TCP].payload):
                print('PP', x[TCP].payload)
                res.append(x[TCP].payload)
                return True

        t = AsyncSniffer(filter="tcp src port 30031", count=10, timeout=4, stop_filter=sn)
        t.start()
        t.join()

        """for res in t.results:
            print(res)
            if b"#DER#343#" in res:
                q = res
            else:
                continue"""
        
        print('API DONE', res[0])

        self.writer.api.append(['get_id', [bytes(res[0])]])

        self.myseq += len(PA[TCP].payload.load)

    def send_message(self, text, nick, level, suppressors, sex, title, avatar, bubble, frame):
        lx = b'\xfc\x01\x00\x00'
        PA = TCP(sport=self.src_port, dport=self.dst_port, flags='PA', window=512, seq=self.myseq, ack=self.myack)/Raw(load=lx)
        srp1(self.ip/PA, verbose=False)

        #self.myseq += len(lx)

        ## MESSAGE
        lx = "1000000000000a000c000400000008000a0000006d040000e0010000100000000c0010000400080000000c000c00000009000000a8060000c001000014000000100018000400080000000c0010001400100000000100000008010000c800000010000000040000000000000000000000ac000000656a652063687574636875742069206d6e6520757061646574206368617365722079612064756d61752e20766f7420747574203c686f7420746578747374796c653d226c6f636174696f6e2220706172616d3d223526494d46494e455448414e4b53414c4c265152534c5f5026417374726126583d2d34333139362e31303220593d36353732372e323033205a3d2d31303030312e393532223e4173747261282d3433312c363537293c2f3e00000000200000003434383034413735343842393246453742443341424241453144304144423742000016002c002400040008000c001000140018001c00200016000000840000001b000000010000006c00000054000000380000001c0000000c000000f2010100e83200000400000030325f330000000011000000546573744176617461724672616d653032000000110000004176617461725f4f766572736561735f310000000c000000636861745f716970616f33310000000007000000315f355f315f31000f000000494d46494e455448414e4b53414c4c00"
        
        token = list(secrets.token_hex(16).upper())
        token[8] = "4"
        token = ''.join(token).encode("UTF_8")

        lx = bytearray.fromhex(lx)

        lx = lx.replace(b"44804A7548B92FE7BD3ABBAE1D0ADB7B", token)

        text = text.encode("UTF_8")
        nulls = "\x00" * (172 - len(text))
        text = (text.decode("UTF_8") + nulls).encode("UTF_8")

        nick = nick.encode("UTF_8")
        nick_nulls = "\x00" * (15 - len(nick))
        nick = (nick.decode("UTF_8") + nick_nulls).encode("UTF_8")

        level = i2h(int(level))
        level_nulls = "\x00" * (3 - len(level))
        level = level + level_nulls.encode("UTF_8")

        suppressors = b"0" + suppressors.encode("UTF_8") # 6_3 = 06_3

        sex = binascii.unhexlify("0" + str(sex))

        title = title.encode("UTF_8")

        if bubble != "Default":
            bubble = ("chat_qipao" + str(bubble)).encode("UTF_8")
        else:
            bubble = "Default\x00\x00\x00\x00\x00".encode("UTF_8")
        
        if int(frame) >= 0:
            if frame < 10:
                frame = ("AvatarFrame0" + str(frame) + "\x00\x00\x00\x00").encode("UTF_8")
            else:
                frame = ("AvatarFrame" + str(frame) + "\x00\x00\x00\x00").encode("UTF_8")
        else:
            if frame > -10: 
                frame = ("TestAvatarFrame0" + str(abs(frame))).encode("UTF_8")
            else:
                frame = ("TestAvatarFrame" + str(abs(frame))).encode("UTF_8")

        ava = avatar.encode("UTF_8")
        ava_nulls = "\x00" * (17 - len(ava))
        ava = (ava.decode("UTF_8") + ava_nulls).encode("UTF_8")



        lx = lx.replace(b"""eje chutchut i mne upadet chaser ya dumau. vot tut <hot textstyle="location" param="5&IMFINETHANKSALL&QRSL_P&Astra&X=-43196.102 Y=65727.203 Z=-10001.952">Astra(-431,657)</>""", text)

        lx = lx.replace(b"TestAvatarFrame02", frame) # Frame
        lx = lx.replace(b"IMFINETHANKSALL", nick) #НИК
        lx = lx.replace(b"\x84\x00\x00\x00\x1b\x00\x00", b"\x84\x00\x00\x00" + level) #LVL
        lx = lx.replace(b"\x01\x00\x00\x00\x6c", sex + b"\x00\x00\x00\x6c") # ГЕНДЕР
        lx = lx.replace(b"chat_qipao31", bubble) # Бабл
        lx = lx.replace(b"02_3", suppressors) # Сапрессор
        lx = lx.replace(b"1_5_1_1", title) # Титул
        lx = lx.replace(b"Avatar_Overseas_1", ava)

        payload = lx

        PA = self.ip/TCP(sport=self.src_port, dport=self.dst_port, flags='PA', reserved=0, window=4149, seq=self.myseq, ack=self.myack)/Raw(load=payload)
        PA[TCP].window = 512
        PA[TCP].dataofs = 5

        del PA[IP].ihl
        del PA[TCP].chksum
        del PA[IP].chksum

        PA.show2()

        sendp(PA)

        self.myseq += len(PA[TCP].payload.load)

    def run(self):
        self.connect()
        sniff(prn=self.pkt_callback, filter="tcp src port 30031", store=0)

class InputStream(Thread):
    def __init__(self, sniffer, helper):
        Thread.__init__(self)
        self.queue = []
        self.sniffer = sniffer
        self.helper = helper
        self.api_table = {
            "get_id":  self.sniffer.api_get_id,
            "get_info": self.sniffer.api_get_info
        }
    
    def run(self):
        while True:
            if self.queue:
                try:
                    js = self.queue[0]
                    del self.queue[0]
                    print("JS", js)

                    if type(js) == list:
                        sock = js[0]
                        js = js[1]

                    js = json.loads(js)
                    print(js)

                    if len(js.keys()) < 8:
                        if "type" in js.keys():
                            if "params" not in js.keys():
                                js["params"] = None

                            self.helper.queue.append([self.api_table[js["type"]], [js["query"], js["params"]]])
                            self.sniffer.writer.queries[f'{js["type"]}/{js["query"]}'] = sock

                            print("Q/S", self.helper.queue)
                        else:
                            continue

                    else:
                        self.sniffer.send_message(text=js["text"], nick=js["nickname"], suppressors=js["suppressors"], sex=js["sex"],
                                                title=js["title"], level=js["level"], avatar=js["avatar"], bubble=js["bubble"], frame=js["frame"])
                except Exception as e:
                    print('INP', e)
                    pass
            
            time.sleep(0.5)

class Writer(Thread):
    def __init__(self):
        Thread.__init__(self)
        self.queue = []
        self.queries = {}
        self.pattern = regex.compile("""(?:(?<hash_id>[A-Z0-9]{33}).*(?<avatar_frame>AvatarFrame\\d+)(?<avatar>.*?)(?:chat_qipao|Default)(?<identifiers>(?:\\d+\\_?|none)+))(?<nickname>.*?)$""")
        self.to_stream = []
        self.to_stream_point = []
        self.api = []

        self.api_table = {
            "get_id": self.api_get_id,
            "get_info": self.api_get_info
        }

    def api_get_info(self, payload, *args, **kwargs):
        return {"type": "get_info", "query": args[0], "answer": str(payload.split(b"\x00"))}

    def api_get_id(self, payload, *args, **kwargs):
        stream = list(filter(lambda x: len(x) > 0 and x != b" ", payload.split(b"\x00")))

        print(stream)

        nick = stream[-7].decode()
        pid = int(stream[-5].decode())
        print(pid)

        return {"type": "get_id", "query": nick, "answer": pid}

    def run(self):
        with open("chat.txt", "a", encoding='utf8') as f:
            print('OPEN')
            while True:
                if self.api:
                    print('API')

                    print(self.queries)
                    try:
                        anws = self.api_table[self.api[0][0]](*self.api[0][1])
                        del self.api[0]

                        sock = self.queries[f'{anws["type"]}/{anws["query"]}']
                        del self.queries[f'{anws["type"]}/{anws["query"]}']
                        self.to_stream_point.append([sock, anws])
                        print("ABC")

                    except Exception as e:
                        print('IN API', e)
                        del self.api[0]

                        try:
                            del self.queries[f'{anws["type"]}/{anws["query"]}']
                        except:
                            pass

                if self.queue:
                    print('CHAT')

                    try:
                        sticker = False
                        if b"hottaemoji" in self.queue[0] or b"#1#big" in self.queue:
                            sticker = True

                        stream = list(filter(lambda x: len(x) > 0 and x != b" ", self.queue[0][140:].split(b"\x00")))
                        stream_copy = copy.copy(stream)
                        stream_copy.reverse()

                        name = stream[-1].decode("UTF_8")

                        Bubble = stream[-5].decode("UTF_8")
                        if len(Bubble) == 1:  
                            AvatarFrame = stream[-6].decode("UTF_8")
                            Avatar = stream[-5].decode("UTF_8")
                            Bubble = stream[-4].decode("UTF_8")
                        else:
                            AvatarFrame = stream[-9].decode("UTF_8")
                            Avatar = stream[-7].decode("UTF_8")

                        smth = stream[-3].decode("UTF_8")
                        t = int(time.time())

                        msg = ""
                        print(stream_copy)

                        for s in stream_copy:
                            try:
                                u = s.decode("UTF_8")
                                if not "\\x" in repr(u):
                                    if len(u) == 32:
                                        hash_id = u
                                        break
                            except Exception as e:
                                print(e)
                                pass
                            
                        for s in stream:
                            try:
                                u = s.decode("UTF_8")
                                if not "\\x" in repr(u):
                                    if u != hash_id:
                                        msg += u + " "
                                    else:
                                        break
                            except:
                                pass
                        
                        print(msg, name)

                        if '\"employ\"' in msg:
                            ty = "RECRUIT_CHAT"
                        else:
                            ty = "WORLD_CHAT"

                        pload = json.dumps({"type": ty, "hash_id": hash_id, "nickname": name, "message": msg if not(sticker) else "", "sticker": msg if sticker else "",
                                "AvatarFrame": AvatarFrame, "Avatar": Avatar, "Bubble": Bubble, "misc": smth, "timestamp": t})
                        
                        print("APPENDED")
                        self.to_stream.append(["all", pload])
                        print("DONE")

                        text = f"{pload}\n"
                        f.write(text)
                        f.flush()
                        os.fsync(f)
                        del self.queue[0]
                    except Exception as e:
                        print("ERROR IN CHAT WRITE", e) 
                time.sleep(0.05)

class ApiHelper(Thread):
    def __init__(self):
        Thread.__init__(self)
        self.queue = []
    
    def run(self):
        while True:
            try:
                if self.queue:
                    print("HELPER")
                    func = self.queue[0]
                    del self.queue[0]
                    print("HELPER QUEUE CLEAR")

                    func[0](func[1][0], func[1][1])
            except Exception as e:
                print(e)
                try:
                    del self.queue[0]
                except Exception as e:
                    pass
            time.sleep(0.1)

class WebApp(Thread):
    def __init__(self, writer, input):
        Thread.__init__(self)
        self.writer = writer
        self.input = input

    async def register(self, websocket):
        CONNECTIONS.add(websocket)

        try:
            async for load in websocket:
                if load == "ping":
                    await websocket.send(json.dumps({"type": "PING"}))
                elif load == "unsub":
                    CONNECTIONS.remove(websocket)
                else:
                    self.input.queue.append([websocket, load])
        except:
            pass

        try:
            await websocket.wait_closed()
        finally:
            try:
                CONNECTIONS.remove(websocket)
            except:
                pass

    async def send(self):
        while True:
            try:
                if self.writer.to_stream:
                    if self.writer.to_stream[0][0] == "all":
                        message = self.writer.to_stream[0][1]
                        del self.writer.to_stream[0]

                        print(f">>> {message}")
                        websockets.broadcast(CONNECTIONS, message)
                elif self.writer.to_stream_point:
                    sock = self.writer.to_stream_point[0][0]
                    to_stream = self.writer.to_stream_point[0][1]

                    del self.writer.to_stream_point[0]

                    await sock.send(json.dumps(to_stream))

            except Exception as e:
                print('SEND', e)

                try:
                    del self.writer.to_stream[0]
                except:
                    pass
                try:
                    del self.writer.to_stream_point[0]
                except:
                    pass
                    
            
            await asyncio.sleep(0.4)
    
    async def main(self):
        async with websockets.serve(self.register, "0.0.0.0", 25565):
            await asyncio.gather(self.send(),) #self.recv())
    
    def run(self):
        asyncio.run(self.main())
    
'''class DROPRST(Thread):
    def __init__(self):
        Thread.__init__(self)

    def run(self):
        with pydivert.WinDivert("tcp.DstPort == 30031") as w:
            for packet in w:
                if packet.tcp.rst and packet.tcp.dst_port == 30031:
                    continue

                w.send(packet)'''

if __name__=="__main__":
    apihelper = ApiHelper()
    wr = Writer()
    sn = Sniffer(writer=wr)
    inp = InputStream(sniffer=sn, helper=apihelper)
    wa = WebApp(writer=wr, input=inp)
    #dr = DROPRST()

    #dr.start()
    time.sleep(0.5)
    apihelper.start()
    sn.start()
    wr.start()
    wa.start()
    inp.start()
