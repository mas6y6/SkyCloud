import websockets
import json
import os
import sys
import traceback
from websockets.asyncio.server import serve, ServerConnection, Server
import logging
import yaml
import sqlite3
import asyncio
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from skycloud.auth import AuthHandler, Session
from skycloud.permissions import Permissions, PERMISSIONS

if not os.path.exists("./config.yml"):
    print("config.yml not found creating new one")
    with open("config.yml", "w") as f:
        f.write(
            """configversion: 1
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
  

"""
        )

config = yaml.safe_load(open("config.yml"))

logging.basicConfig(
    level=logging.INFO, format="[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s"
)
skycloudlogger = logging.getLogger("SkyCloud")
skycloudlogger.info("Starting SkyCloud Server")

if config["database"]["type"]:
    database = sqlite3.connect(config["database"]["path"], check_same_thread=False)
else:
    skycloudlogger.fatal("Database Type is not supported!", exc_info=True)
    sys.exit(1)

authhandler = AuthHandler(database)

databaseempty = False
if authhandler.is_empty():
    skycloudlogger.warning(
        "Your user database is empty. Your server will request a user register upon connection"
    )
    databaseempty = True

version = 1.0
server = Server
motd = config["server"]["motd"]
port = config["server"]["port"]
host = config["server"]["host"]
maxconnections = config["server"]["maxconnections"]
compression = config["server"]["compression"]
signinmethods = ["signin"]
sessionbackgroundthreads = None
killswitch = False
sessionlogger = logging.getLogger("SessionHandler")
if config["authorization"]["use_key_based_signin"]:
    signinmethods.append("rsakey")

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()
serialized_public_key = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)
skycloudlogger.info("Generated RSA keys")


async def handler(websocket: ServerConnection):
    logger = logging.getLogger(f"ConnectionHandler ({websocket.remote_address})")
    logger.info(f"Connection Established from {websocket.remote_address}")
    await websocket.send(
        json.dumps(
            {
                "type": "handshake",
                "version": version,
                "motd": motd,
                "compression": compression,
            }
        )
    )
    await websocket.send(
        json.dumps({"type": "encryption", "key": serialized_public_key.decode()})
    )

    logger.info("Client accepted Handshake request.")
    session = None
    authstatus = "NULL"
    encrypted_symmetric_key = await websocket.recv()
    symmetric_key = private_key.decrypt(
        encrypted_symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    cipher = Fernet(symmetric_key)

    async def send(data):
        encrypted_message = cipher.encrypt(data.encode())
        await websocket.send(encrypted_message)

    async def recv_str():
        encrypted_message = await websocket.recv()
        return cipher.decrypt(encrypted_message).decode()

    async def recv_bytes():
        encrypted_message = await websocket.recv()
        return cipher.decrypt(encrypted_message)

    test = json.loads(await recv_str())
    if test["type"] == "encryption_test" and test["msg"] == "test":
        await send(json.dumps({"type": "encryption_test", "msg": "success"}))

    logger.info("Encryption Successful")
    logger.info("Handshake complete. Starting Authorization")

    if authhandler.is_empty():
        await send(json.dumps({"type": "register"}))
        authstatus = "REGISTER"
    else:
        await send(json.dumps({"type": "signin", "methods": signinmethods}))
        authstatus = "SIGNIN"

    while session == None:
        if authstatus == "REGISTER":
            regdata = json.loads(await recv_str())
            if regdata["type"] == "register":
                if authhandler.is_empty():
                    perm = Permissions(4)
                else:
                    perm = Permissions(regdata["permissions"])
                session = authhandler.register_user(
                    regdata["username"],
                    password=regdata["password"],
                    permissions=perm,
                    websocket=websocket,
                )
                await send(
                    json.dumps({"type": "auth", "sessionid": session.sessionuuid})
                )
            else:
                await websocket.close(reason="ILLEGAL_OPERATION")
        else:
            signdata = json.loads(await recv_str())
            if signdata["type"] == "signin/signin":
                session = authhandler.login_user(
                    username=signdata["username"],
                    password=signdata["password"],
    
                    websocket=websocket,
                )
                if session == None:
                    await send(
                        json.dumps({"type": "msg", "message": "INVALID_CREDENTIALS"})
                    )
                else:
                    await send(
                        json.dumps({"type": "auth", "sessionid": session.sessionuuid})
                    )
            else:
                await websocket.close(reason="ILLEGAL_OPERATION")

async def session_ticker():
    while killswitch == False:
        for i in authhandler.sessions.items():
            if i[1].alive == False:
                i[1].close()
                del authhandler.sessions[i[0]]
            i[1].tick()
        await asyncio.sleep(1)

# From here it starts getting chaos as I am very new to asyncio so its kinda hard for me to understand
# how to properly implement this.
#
# So yea please dont main the DeprecationWarning for ./SkyCloud/main.py:225
# as I need to run background tasks for the session tickers and pingers
#
# - mas6y6

def session_ticker_starter():
    asyncio.run(session_ticker)

def session_pinger_starter():
    pass

async def main():
    global server
    await start_background_tasks()
    server = await serve(
        handler=handler,
        host=host,
        port=port,
        logger=logging.getLogger("WebsocketLogger"),
    )

    await server.wait_closed()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        skycloudlogger.info("Shutdown Signal Detected. Shutting Down Server and internal threads.")
        killswitch = True