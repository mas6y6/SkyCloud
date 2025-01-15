import cryptography, asyncio, json, os, sys, time, requests, random, string, lzma
from websockets.sync.server import serve, ServerConnection
import logging, yaml, sqlite3, bcrypt, uuid
from skycloud.auth import AuthHandler

if not os.path.exists("./config.yml"):
    print("Configfile not found creating new one")
    with open("config.yml", "w") as f:
        f.write("""configversion: 1
# Do not change this value

server:
  host: "localhost"
  motd: "Skycloud Server"
  port: 3127
  maxconnections: 10

database:
  file: "./skycloud.db"

logging:
  level: "INFO"
  file: "./skycloud.log"
""")

config = yaml.safe_load(open("config.yml"))

logging.basicConfig(level=logging.INFO,format='[%(asctime)s] [%(name)s] [%(levelname)s]: %(message)s')
skycloudlogger = logging.getLogger("SkyCloud")
skycloudlogger.info("Starting SkyCloud Server...")

authhandler = AuthHandler(config["database"]["file"])

version = 1.0
motd = config["server"]["motd"]
port = config["server"]["port"]
host = config["server"]["host"]
maxconnections = config["server"]["maxconnections"]

def handler(websocket: ServerConnection):
    websocket.send(json.dumps({"type": "handshake", "version": version, "motd": motd}))
    websocket.send({"type":"handshake","version":version,"motd":""})