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
skycloudlogger.info("Starting SkyCloud Server...")

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
skycloudlogger.info("Generated RSA keys beginning to start server...")

def handler(websocket):
    # Step 1: Send the server's public RSA key to the client
    websocket.send(json.dumps({"type": "public_key", "key": serialized_public_key.decode()}))

    # Step 2: Receive the encrypted symmetric key from the client
    encrypted_symmetric_key = websocket.recv()
    symmetric_key = private_key.decrypt(
        encrypted_symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Step 3: Initialize the Fernet cipher with the symmetric key
    cipher = Fernet(symmetric_key)

    # Step 4: Encrypt and send a handshake message to the client
    handshake_message = json.dumps({"type": "handshake", "version": version, "motd": motd})
    encrypted_message = cipher.encrypt(handshake_message.encode())
    websocket.send(encrypted_message)