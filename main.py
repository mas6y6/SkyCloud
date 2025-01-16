import cryptography, asyncio, json, os, sys, time, requests, random, string, lzma
from websockets.sync.server import serve, ServerConnection
import logging, yaml, sqlite3, bcrypt, uuid
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
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
skycloudlogger.info("Starting SkyCloud Server")

authhandler = AuthHandler(config["database"]["file"])

version = 1.0
motd = config["server"]["motd"]
port = config["server"]["port"]
host = config["server"]["host"]
maxconnections = config["server"]["maxconnections"]

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()
serialized_public_key = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
skycloudlogger.info("Generated RSA keys")

def handler(websocket: ServerConnection):
    # Send initial handshake
    websocket.send(json.dumps({"type": "handshake", "version": version, "motd": motd}))
    websocket.logger.info(f"Connection Established to {websocket.remote_address}")

    # Send public key
    websocket.send(json.dumps({"type": "handshake", "key": serialized_public_key.decode()}))

    # Receive encrypted symmetric key
    encrypted_symmetric_key = websocket.recv()
    symmetric_key = private_key.decrypt(
        encrypted_symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    cipher = Fernet(symmetric_key)

    def send(data):
        encrypted_message = cipher.encrypt(data.encode())
        websocket.send(encrypted_message)

    def recv():
        encrypted_message = websocket.recv()
        return json.loads(cipher.decrypt(encrypted_message).decode())

    # Receive encryption test
    test = recv()
    if test["type"] == "encryption_test" and test["msg"] == "test":
        # Respond to encryption test
        send(json.dumps({"type": "encryption_test", "msg": "success"}))
    
    
      
server = serve(handler=handler,host=host, port=port, logger=logging.getLogger("Server"))
skycloudlogger.info(f"Server started on {host}:{port}")
server.serve_forever()