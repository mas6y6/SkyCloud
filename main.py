import cryptography, asyncio, json, os, sys, time, requests, random, string, lzma
from websockets.asyncio.server import serve, ServerConnection
import logging, yaml, sqlite3, bcrypt, uuid, asyncio
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from skycloud.auth import AuthHandler

if not os.path.exists("./config.yml"):
    print("config.yml not found creating new one")
    with open("config.yml", "w") as f:
        f.write("""configversion: 1
# Do not change this value

server:
  host: "localhost"
  motd: "Skycloud Server"
  port: 3127
  maxconnections: 10
  compression: true

authorization:
  use_key_based_signin: true

database:
  type: "sqlite"
  path: "./skycloud.db"

logging:
  level: "INFO"
  path: "./skycloud.log"
  

""")

config = yaml.safe_load(open("config.yml"))

logging.basicConfig(level=logging.INFO,format='[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s')
skycloudlogger = logging.getLogger("SkyCloud")
skycloudlogger.info("Starting SkyCloud Server")

if config["database"]["type"]:
    database = sqlite3.connect(config["database"]["path"], check_same_thread=False)
else:
    skycloudlogger.fatal("Database Type is not supported!",exc_info=True)
    sys.exit(1)

authhandler = AuthHandler(database)

databaseempty = False
if authhandler.is_empty():
    skycloudlogger.warning("Your user database is empty. Your server will request a user register upon connection")
    databaseempty = True

version = 1.0
motd = config["server"]["motd"]
port = config["server"]["port"]
host = config["server"]["host"]
maxconnections = config["server"]["maxconnections"]
compression = config["server"]["compression"]
signinmethods = ["signin"]
if config["authorization"]["use_key_based_signin"]:
    signinmethods.append("rsakey")

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()
serialized_public_key = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
skycloudlogger.info("Generated RSA keys")

async def handler(websocket: ServerConnection):
    logger = logging.getLogger(f"ConnectionHandler ({websocket.remote_address})")
    logger.info(f"Connection Established from {websocket.remote_address}")
    await websocket.send(json.dumps({"type": "handshake", "version": version, "motd": motd,"compression":compression}))
    await websocket.send(json.dumps({"type": "encryption", "key": serialized_public_key.decode()}))

    logger.info("Encrypting connection")
    session = None
    encrypted_symmetric_key = await websocket.recv()
    symmetric_key = private_key.decrypt(
        encrypted_symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    cipher = Fernet(symmetric_key)

    async def send(data):
        encrypted_message = cipher.encrypt(data.encode())
        await websocket.send(encrypted_message)

    async def recv():
        encrypted_message = await websocket.recv()
        return cipher.decrypt(encrypted_message).decode()

    test = await json.dumps(recv())
    if test["type"] == "encryption_test" and test["msg"] == "test":
        await send(json.dumps({"type": "encryption_test", "msg": "success"}))
    
    if authhandler.is_empty():
        await send(json.dumps({"type":"register"}))
    else:
        await send(json.dumps({"type":"signin","methods":signinmethods}))
    logger.info("Encryption Successful")
    
    while session == None:
        signin_data = await json.loads(recv())
        signin_data
            

async def main():
    server = await serve(handler=handler,host=host, port=port, logger=logging.getLogger("WebsocketLogger"))
    await asyncio.get_running_loop().create_future()
    
if __name__ == "__main__":
    asyncio.run(main())