import json

import time
from threading import Thread
from IternalAPI.IternalAPI import IternalAPI


class InputStreamHandler(Thread):
    def __init__(self, GameConnection, ApiHelper):
        Thread.__init__(self)
        self.QUEUE = []
        self.GameConnection = GameConnection
        self.ApiHelper = ApiHelper
    
    def run(self):
        while True:
            if self.QUEUE:
                try:
                    js = self.QUEUE[0]
                    del self.QUEUE[0]

                    if type(js) == list:
                        sock = js[0]
                        js = js[1]

                    js = json.loads(js)

                    if "type" in js.keys():
                        self.ApiHelper.QUEUE.append([IternalAPI.get_api(js["type"]), self.GameConnection, js])
                        
                        if "query" in js.keys():
                            self.GameConnection.OutputStreamer.QUERIES[f'{js["type"]}/{js["query"]}'] = sock
                    else:
                        continue

                except Exception as e:
                    print('INP', e)
                    pass
            
            time.sleep(0.5)
