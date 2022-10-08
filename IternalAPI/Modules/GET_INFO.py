from ..IternalAPIInterface import ApiModule
from scapy.all import *


class GET_INFO(ApiModule):
    def parse(payload, *args, **kwargs):
        ans = payload.split(b"\x00")
        ans = list(filter(lambda x: len(x) > 0 and x != b" ", ans))
        ans = ' '.join(list(map(lambda x: x.decode("UTF_8", errors='ignore'), ans)))

        return {"type": "GET_INFO", "query": args[0], "answer": ans}

    def get_desc():
        return "GET INFO ABOUT PLAYER BY ID"

    def run(GameConnection, query, *args, **kwargs):
        pid = str(query)

        lx = b'\x80\x00\x00\x00'
        PA = TCP(sport=GameConnection.SRC_PORT, dport=GameConnection.DST_PORT, flags='PA', window=512, seq=GameConnection.myseq, ack=GameConnection.myack)/Raw(load=lx)
        srp1(GameConnection.ip/PA, verbose=False, timeout=1)

        lx = "1000000000000a000c000400000008000a0000007004000064000000100000000c0010000400080000000c000c0000000a0000003f010000440000001400000000000e0014000400080000000c0010000e0000001800000061ae0a00080000001200000000000000000000000e00000035353937323031333830333739390000"
        lx = bytearray.fromhex(lx)

        lx = lx.replace(b"55972013803799", pid.encode("UTF_8"))

        PA = GameConnection.ip/TCP(sport=GameConnection.SRC_PORT, dport=GameConnection.DST_PORT, flags='PA', reserved=0, window=4149, seq=GameConnection.myseq, ack=GameConnection.myack)/Raw(load=lx)
        PA[TCP].window = 512
        PA[TCP].dataofs = 5

        del PA[IP].ihl
        del PA[TCP].chksum
        del PA[IP].chksum

        PA.show2()
        sendp(PA)
        
        total = []

        def sr(x):
            if len(x[TCP].payload) > 300 and not(b"\xa9\x06\x00\x00" in bytes(x[TCP].payload)) and not(b"127.0.0.1" in bytes(x[TCP].payload)):
                total.append(bytes(x[TCP].payload))
            if b"NameReportID" in bytes(x[TCP].payload):
                return True

        t = AsyncSniffer(filter="tcp src port 30031", count=25, timeout=5, stop_filter=sr)
        t.start()
        t.join()

        total = b''.join(total)
        
        GameConnection.OutputStreamer.API_QUEUE.append(['GET_INFO', [total, pid]])
