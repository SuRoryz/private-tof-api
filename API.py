from flask import Flask, request, render_template, jsonify
from flask_sock import Sock
from turbo_flask import Turbo
import os
import json
from flask_cors import CORS
from websocket import create_connection 
import json

app = Flask(__name__)

app.config['JSON_AS_ASCII'] = False

CORS(app)

def LastNlines(fname, N):

    assert N >= 0
    pos = N + 1

    lines = []

    with open(fname) as f:
        while len(lines) <= N:
            try:
                f.seek(-pos, 2)
            except IOError:
                f.seek(0)
                break
            finally:
                lines = list(f)

            pos *= 2

    return lines[-N:]

@app.route("/api/get_resources", methods=["GET", "POST"])
def resources():
   js = {"items": {
         "bubble": {
            "Affection_Buble": 36,
            "Champion_Shopkeeper": 17,
            "Default": 'Default',
            "Hanging_Amusement_Park": 16,
            "Holiday_Fun": '',
            "Midnight_Logic": 28,
            "Past_Days": 26,
            "Pawpaw_Dreamscape": 27,
            "Proud_Blade": 13,
            "Pumpkin_Party": 29,
            "Set_off_Again": 31,
            "Summer_Stream": 41,
            "Together_Time": 22,
            "Under_the_Thumb": 12,
            "Vanity_of_Life": 30,
         },
         "avatar": {
            "NoAvatar": 'Avatar36',
            "Claudia": 'Avatar35',
            "Initial_Avatar_Famale": 'Avatar01',
            "Initial_Avatar_Male": 'Avatar02',
            "Shirli": '',
            "Nemesis": '',
            "Nemesis_Awakening": '',
            "Samir": 'Avatar29',
            "Pepper": '',
            "Zeke_Awakening": '',
            "Meryl": '',
            "Echo": '',
            "Bai_Ling": '',
            "Cabalt-B": '',
            "Hilda": '',
            "Cocoritter": '',
            "KING": '',
            "Zero": '',
            "Tsubasa": '',
            "Crow": '',
            "Ene": '',
            "Shiro": '',
            "Huma": '',
            "Frigg": 'Avatar05',
            "Angel_Frigg": 'Avatar12',
            "Alf": '',
            "Peanut": 'Avatar14',
            "Smarty": 'Avatar15',
            "Mad_Dimon": 'Avatar16',
            "Tartarus": 'Avatar17',
            "Strawberry_Afternoon": 'Avatar22',
            "Kitty_Coast": 'Avatar26',
            "noname1": 'Avatar08',
            "noname2": 'Avatar07',
            "noname3": 'Avatar04',
            "noname4": 'Avatar09',
            "noname5": 'Avatar10',
            "noname6": 'Avatar11',
            "noname7": 'Avatar18',
            "noname8": 'Avatar19',
            "noname9": 'Avatar20',
            "noname10": 'Avatar21',
            "noname11": 'Avatar30',
            "noname12": 'Avatar34',
         },
         "frame": {
            "Champion_Shopkeeper": 17,
            "Metal": -1,
            "Wreath": -2,
            "Shining_Star": 3,
            "Leader_of_Astra": 4,
            "Executor": 11,
            "Tower\'s_Core": 12,
            "Gaze_Mirroria": 30,
            "Salty_Wave": 40,
            "Cordate_Jellybean": 35,
            "Island_Fantasy": 25,
            "Knight_of_Night": 26,
            "Pawpaw_Treasure": 27,
            "Pumpkin_Night": 28,
            "Memories": 29,
            "noname1": 23,
            "noname2": 22,
            "noname3": 20,
            "noname4": 5,
            "noname5": 6,
            "noname6": 8,
            "noname7": 9,
            "noname8": 10,
            "noname9": 13,
            "noname10": 16,
            "noname11": 18,
            "naname12": 33,
            "noname13": 34,
         },
         "title": {
            'Astra Cartographer': '1_1_1_1',
            'Soaring High': '1_2_1_1',
            'Banges Apprentice': '1_1_2_1',
            'Park Ranger': '1_1_3_1',
            'Commander': '1_3_1_1',
            'Extrem Climber': '1_1_8_1',
            'Top Climber': '1_1_8_2',
            'Snowfield Investigator': '1_1_5_1',
            'Elite': '1_1_8_3'
         },
         "suppressors": {
            '1.0': '1_0',
            '1.1': '1_1',
         },
         "sex": {
            "famale": 0,
            "male": 1,
         },
         "colors": {
            "ITEM_QUALITY_LEGENDARY": {
                  "color": 'ItemQualityLegendary',
                  "html": '<EmployNotice>$1</>',
            },
            "RED": {
                  "html": '<Lblred>$1</>'
            },
            "EMPLOY": {
                  "color": 'employ',
                  "description": 'green color',
            },
         }
      }
   }

   return jsonify(js)

@app.route("/api/update", methods=["GET", "POST"])
def update():
   if request.method == 'GET':
      count = request.args.get('count', default=50, type=int)

   if request.method == 'POST':
      if 'count' in request.form:
         count = int(request.form.get('count'))
      else:
         count = 50
   
   lines = LastNlines("chat.txt", count)

   anw = {'items': []}
   for line in lines:
      anw['items'].append(json.loads(line))
   return jsonify(anw)


@app.route("/api/get_id/<name>", methods=["GET"])
def get_id(name):
   try:
      ws = create_connection("ws://62.109.15.182:25565", timeout=3)
      
      ws.send("unsub")
      ws.send(json.dumps({"type": "GET_ID", "query": name}))

      result = ws.recv()
      ws.close()

      return jsonify(json.loads(result))

   except:
      return jsonify({"type": "get_id", "error": 1, "error_msg": "[1]: No such player"})

@app.route("/api/get_info/<pid>", methods=["GET"])
def get_info(pid):
   try:
      ws = create_connection("ws://62.109.15.182:25565", timeout=20)
      
      ws.send("unsub")
      ws.send(json.dumps({"type": "GET_INFO", "query": pid}))

      result = ws.recv()
      ws.close()

      return jsonify(json.loads(result))

   except:
      return jsonify({"type": "GET_INFO", "error": 1, "error_msg": "[1]: No such player"})

app.run(host="0.0.0.0", port=27416)
