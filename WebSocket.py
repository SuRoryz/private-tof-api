import asyncio
import json
import websockets

from threading import Thread


class WebSocket(Thread):
    def __init__(self, OutputStreamer, InputStreamHandler):
        Thread.__init__(self)

        self.CONNECTIONS = set()
        self.OutputStreamer = OutputStreamer
        self.InputStreamHandler = InputStreamHandler

    async def register(self, websocket):
        self.CONNECTIONS.add(websocket)

        try:
            async for load in websocket:
                if load == "ping":
                    await websocket.send(json.dumps({"type": "PING"}))
                elif load == "unsub":
                    self.CONNECTIONS.remove(websocket)
                else:
                    self.InputStreamHandler.QUEUE.append([websocket, load])
        except:
            pass
        try:
            await websocket.wait_closed()
        finally:
            try:
                self.CONNECTIONS.remove(websocket)
            except:
                pass

    async def send(self):
        while True:
            try:
                if self.OutputStreamer.TO_STREAM:
                    if self.OutputStreamer.TO_STREAM[0][0] == "all":
                        message = self.OutputStreamer.TO_STREAM[0][1]
                        del self.OutputStreamer.TO_STREAM[0]

                        websockets.broadcast(self.CONNECTIONS, message)

                elif self.OutputStreamer.TO_STREAM_POINT:
                    sock = self.OutputStreamer.TO_STREAM_POINT[0][0]
                    to_stream = self.OutputStreamer.TO_STREAM_POINT[0][1]
                    del self.OutputStreamer.TO_STREAM_POINT[0]

                    await sock.send(json.dumps(to_stream, ensure_ascii=False))

            except Exception as e:
                print('SEND', e)

                try:
                    del self.OutputStreamer.TO_STREAM[0]
                except:
                    pass
                try:
                    del self.OutputStreamer.TO_STREAM_POINT[0]
                except:
                    pass
                    
            await asyncio.sleep(0.4)

    async def main(self):
        async with websockets.serve(self.register, "0.0.0.0", 25565):
            await asyncio.gather(self.send())
    
    def run(self):
        asyncio.run(self.main())