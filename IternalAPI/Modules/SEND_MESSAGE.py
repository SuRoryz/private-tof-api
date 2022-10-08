import binascii
import sys

from ..IternalAPIInterface import ApiModule
from scapy.all import *

sys.path.append(".../")
from Utils import Utils


class SEND_MESSAGE(ApiModule):
    def get_desc():
        return "GET PLAYER ID BY NAME"

    def run(GameConnection, text, nickname, level, suppressors, sex, title, avatar, bubble, frame):
        lx = b'\xfc\x01\x00\x00'
        PA = TCP(sport=GameConnection.SRC_PORT, dport=GameConnection.DST_PORT, flags='PA', window=512, seq=GameConnection.myseq, ack=GameConnection.myack)/Raw(load=lx)
        srp1(GameConnection.ip/PA, verbose=False)

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

        nick = nickname.encode("UTF_8")
        nick_nulls = "\x00" * (15 - len(nick))
        nick = (nick.decode("UTF_8") + nick_nulls).encode("UTF_8")

        level = Utils.i2h(int(level))
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



        lx = lx.replace(b"""eje chutchut i mne upadet chaser ya dumau. vot tut <hot textstyle="location" param="5&IMFINETHANKSALL&QRSL_P&Astra&X=-43196.102 Y=65727.203 Z=-10001.952">Astra(-431,657)</>""", text
        ).replace(b"TestAvatarFrame02", frame
        ).replace(b"IMFINETHANKSALL", nick
        ).replace(b"\x84\x00\x00\x00\x1b\x00\x00", b"\x84\x00\x00\x00" + level
        ).replace(b"\x01\x00\x00\x00\x6c", sex + b"\x00\x00\x00\x6c"
        ).replace(b"chat_qipao31", bubble
        ).replace(b"02_3", suppressors
        ).replace(b"1_5_1_1", title
        ).replace(b"Avatar_Overseas_1", ava)

        PA = GameConnection.ip/TCP(sport=GameConnection.SRC_PORT, dport=GameConnection.DST_PORT, flags='PA', reserved=0, window=4149, seq=GameConnection.myseq, ack=GameConnection.myack)/Raw(load=lx)
        PA[TCP].window = 512
        PA[TCP].dataofs = 5

        del PA[IP].ihl
        del PA[TCP].chksum
        del PA[IP].chksum

        PA.show2()

        sendp(PA)

        GameConnection.myseq += len(PA[TCP].payload.load)