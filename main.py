import sys
import os
from IternalAPI.ApiHelper import ApiHelper
from OutputStreamHandler import OutputStreamer
from InputStreamHandler import InputStreamHandler
from GameConnection import GameConnection
from WebSocket import WebSocket

sys.path.append("/IternalAPI")
sys.path.append("/IternalAPI/Modules")
os.environ['PATH'] += ':' + "/IternalAPI"
os.environ['PATH'] += ':' + "/IternalAPI/Modules"

if __name__=="__main__":
    AHelper = ApiHelper()
    OStreamer = OutputStreamer()
    GConnection = GameConnection(OutputStreamer=OStreamer)
    IStreamHandler = InputStreamHandler(GameConnection=GConnection, ApiHelper=AHelper)
    WS = WebSocket(OutputStreamer=OStreamer, InputStreamHandler=IStreamHandler)
    
    AHelper.start()
    GConnection.start()
    OStreamer.start()
    WS.start()
    IStreamHandler.start()