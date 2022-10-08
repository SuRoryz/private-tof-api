from ..IternalAPIInterface import ApiModule
from scapy.all import *


class GET_ID(ApiModule):
    def parse(payload, *args, **kwargs):
        stream = list(filter(lambda x: len(x) > 0 and x != b" ", payload.split(b"\x00")))

        nick = stream[-7].decode()
        pid = int(stream[-5].decode())

        return {"type": "GET_ID", "query": nick, "answer": pid}
        
    def get_desc():
        return "GET PLAYER ID BY NAME"

    def run(GameConnection, query, *args, **kwargs):
        player = query

        lx = b'\xd4\x00\x00\x00'
        PA = TCP(sport=GameConnection.SRC_PORT, dport=GameConnection.DST_PORT, flags='PA', window=512, seq=GameConnection.myseq, ack=GameConnection.myack)/Raw(load=lx)
        srp1(GameConnection.ip/PA, verbose=False, timeout=1)

        lx = "1000000000000a000c000400000008000a00000070040000b8000000100000000c0010000400080000000c000c0000000a00000039010000980000002400000000001e003000040008000c001000140018001c00000020000000240028002c001e0000005c00000061ae0a00400000002e020000240000001b0000005a000000100000009e0d00000a000000e803000000000000000000000f000000494d46494e455448414e4b53414c4c000f00000044756d6d79417574685469636b6574000e00000035353937323031333836373530360000"

        lx = bytearray.fromhex(lx)

        player = player.encode("UTF_8")
        player_nulls = "\x00" * (15 - len(player))
        player = (player.decode("UTF_8") + player_nulls).encode("UTF_8")

        lx = lx.replace(b"IMFINETHANKSALL", player)

        PA = GameConnection.ip/TCP(sport=GameConnection.SRC_PORT, dport=GameConnection.DST_PORT, flags='PA', reserved=0, window=4149, seq=GameConnection.myseq, ack=GameConnection.myack)/Raw(load=lx)
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

        GameConnection.OutputStreamer.API_QUEUE.append(['GET_ID', [bytes(res[0])]])
        GameConnection.myseq += len(PA[TCP].payload.load)