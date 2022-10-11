import binascii
from struct import unpack
from ..IternalAPIInterface import ApiModule
from scapy.all import *


class GET_INFO(ApiModule):
    def parse(payload, *args, **kwargs):
        info = payload.hex()

        res = {"Equipment": {},
               "Weapons": {},
               "CS": {}}
               
        info_splitted = binascii.unhexlify(info).split(b"\xff\xff")
        
        for item in info_splitted:
            if b"Equipment_" in item:
                item = list(filter(lambda x: len(x) > 0, item.split(b"\x00")))

                equip_item = item[2].split(b"#")

                equip_name = equip_item[0].decode()
                equip_level = int(equip_item[1])
                equip_stats = {}
                equip_stars = int(equip_item[3])

                for stat in equip_item[2].split(b"|"):
                    stat = stat.split(b";")
                    stat_name = stat[0][2:].decode()
                    stat_value = int(float(stat[1][2:]))

                    equip_stats[stat_name] = stat_value

                res["Equipment"][item[4].decode()] = {
                    "Name": equip_name,
                    "Level": equip_level,
                    "Stats": equip_stats,
                    "Stars": equip_stars
                    }

                continue
                
            if b"HideBattleScore" in item:
                try:
                    redicated = unpack("?", bytes(item.lstrip(b"\x00")[0]))[0]
                except:
                    redicated = True

                res["CS"]["Can u see his CS?"] = "Yes" if redicated else "No"
            
            if b"MaxEnergy" in item:
                energy = int(unpack("f", item[:4])[0])

                res["Endurance"] = energy
                continue

            if b"MaxHP" in item:
                hp = int(unpack("f", item[:4])[0])

                res["MaxHP"] = hp
                continue

            if b"BattleStrengthScore" in item:
                cs = int(unpack("I", item[:4])[0])

                res["CS"]["Here his CS anyway"] = cs
                continue

            if b"\x00Crit\x00" in item:
                crit = int(unpack("f", item[:4])[0])

                res["Crit"] = crit
                continue

            if b"Atk" in item or b"Attack" in item:
                atk = int(unpack("f", item[:4])[0])

                item = list(filter(lambda x: len(x) > 0, item.split(b"\x00")))

                res[item[1].decode()] = atk
                continue

            if b"Defense" in item:
                de = int(unpack("f", item[:4])[0])

                item = list(filter(lambda x: len(x) > 0, item.split(b"\x00")))
                
                res[item[1].decode()] = de
                continue
                
            if b"GuildName" in item:
                item = list(filter(lambda x: len(x) > 0, item.split(b"\x00")))

                guild = item[2].decode()

                res["GuildName"] = guild
                
            if b"Weapon_" in item:
                item = list(filter(lambda x: len(x) > 0, item.split(b"\x00")))
                
                weapon_item = item[2].split(b"#")

                weapon_name = weapon_item[0].decode()
                weapon_level = int(weapon_item[3])

                weapon_stars = int(weapon_item[4].replace(b"&", b"").split(b":")[0])

                res["Weapons"][item[4].decode()] = {
                    "Name": weapon_name,
                    "Level": weapon_level,
                    "Stars": weapon_stars
                    }

                continue

        return {"type": "GET_INFO", "query": args[0], "answer": res}

    def get_desc():
        return "GET INFO ABOUT PLAYER BY ID"

    def run(GameConnection, query, *args, **kwargs):
        print("INFO START")
        try:

            pid = str(query)

            if len(pid) != 14:
                GameConnection.OutputStreamer.API_QUEUE.append(['GET_INFO', ["not valid id", pid]])
                return

            lx = b'\x80\x00\x00\x00'
            PA = TCP(sport=GameConnection.SRC_PORT, dport=GameConnection.DST_PORT, flags='PA', window=512, seq=GameConnection.myseq, ack=GameConnection.myack)/Raw(load=lx)
            sendp(GameConnection.ip/PA, verbose=False)

            time.sleep(0.1)

            lx = "1000000000000a000c000400000008000a0000007004000064000000100000000c0010000400080000000c000c0000000a0000003f010000440000001400000000000e0014000400080000000c0010000e0000001800000061ae0a00080000000700000000000000000000000e00000035353937323031333830333739390000"
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
                if len(x[TCP].payload) > 300 and not(b"\x00\xa9\x06\x00\x00" in bytes(x[TCP].payload)) and not(b"127.0.0.1" in bytes(x[TCP].payload)):
                    total.append(bytes(x[TCP].payload))
                if b"level" in bytes(x[TCP].payload):
                    return True

            t = AsyncSniffer(filter="tcp src port 30031", count=25, timeout=5, stop_filter=sr)
            t.start()
            t.join()

            total = b''.join(total)
            
            GameConnection.OutputStreamer.API_QUEUE.append(['GET_INFO', [total, pid]])

        except Exception as e:
            print("A", e)
