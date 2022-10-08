import os
import json
import time
import copy

from IternalAPI.IternalAPI import IternalAPI
from threading import Thread


class OutputStreamer(Thread):
    def __init__(self):
        Thread.__init__(self)
        self.CHAT_OUT_QUEUE = []
        self.QUERIES = {}
        self.TO_STREAM = []
        self.TO_STREAM_POINT = []
        self.API_QUEUE = []

    def parse_chat(self):
        sticker = False
        if b"hottaemoji" in self.CHAT_OUT_QUEUE[0] or b"#1#big" in self.CHAT_OUT_QUEUE:
            sticker = True

        stream = list(filter(lambda x: len(x) > 0 and x != b" ", self.CHAT_OUT_QUEUE[0][140:].split(b"\x00")))
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

        if '\"employ\"' in msg:
            ty = "RECRUIT_CHAT"
        else:
            ty = "WORLD_CHAT"

        pload = json.dumps({"type": ty, "hash_id": hash_id, "nickname": name, "message": msg if not(sticker) else "", "sticker": msg if sticker else "",
                "AvatarFrame": AvatarFrame, "Avatar": Avatar, "Bubble": Bubble, "misc": smth, "timestamp": t})
        
        return pload

    def run(self):
        with open("chat.txt", "a", encoding='utf8') as f:
            while True:
                if self.API_QUEUE:
                    try:
                        _temp = self.API_QUEUE[0]
                        del self.API_QUEUE[0]

                        anws = IternalAPI.get_api(_temp[0]).parse(*_temp[1])

                        sock = self.QUERIES[f'{anws["type"]}/{anws["query"]}']
                        del self.QUERIES[f'{anws["type"]}/{anws["query"]}']

                        self.TO_STREAM_POINT.append([sock, anws])

                    except Exception as e:
                        print('IN API', e)
                        del self.API_QUEUE[0]

                        try:
                            del self.QUERIES[f'{anws["type"]}/{anws["query"]}']
                        except:
                            pass

                if self.CHAT_OUT_QUEUE:
                    try:
                        pload = self.parse_chat()

                        self.TO_STREAM.append(["all", pload])

                        text = f"{pload}\n"
                        f.write(text)
                        f.flush()
                        os.fsync(f)

                        del self.CHAT_OUT_QUEUE[0]
                    except Exception as e:
                        print("ERROR IN CHAT WRITE", e)

                time.sleep(0.05)