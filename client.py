import json
import threading
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from websockets.sync.client import connect
import logging


class SkyCloudClient:
    def __init__(
        self, host, port=3127, ssl=None, keepalive=True, keepalive_daemon=False
    ):
        if ssl == None:
            self.uri = f"ws://{host}:{port}"
        else:
            self.uri = f"wss://{host}:{port}"

        self.keepalivethread = threading.Thread(target=self.keepalive)
        self.status = "CONNECTING"
        self.killswitch = False
        try:
            self.websocket = connect(self.uri, ssl=ssl)
        except Exception as e:
            raise ConnectionError(f"Failed to connect to server: {e}")
        handshake = json.loads(self.websocket.recv())
        self.compression = handshake["compression"]

        self.status = "ENCRYPTING CONNECTION"
        public_key_message = self.websocket.recv()
        public_key_data = json.loads(public_key_message)
        server_public_key = serialization.load_pem_public_key(
            public_key_data["key"].encode()
        )

        symmetric_key = Fernet.generate_key()
        self.cipher = Fernet(symmetric_key)
        encrypted_symmetric_key = server_public_key.encrypt(
            symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        self.websocket.send(encrypted_symmetric_key)

        self._send(json.dumps({"type": "encryption_test", "msg": "test"}))

        response = json.loads(self._recv())
        if response["type"] == "encryption_test" and response["msg"] == "success":
            pass
        else:
            raise ValueError(
                "Encryption test failed. Terminating (Contact server admin for assistence)"
            )

        self.authorized = False
        self.signin_methods = []

        self._signindata = json.loads(self._recv())
        if self._signindata["type"] == "signin":
            self.signin_methods = self._signindata["methods"]
            self.status = "LOGIN"
        elif self._signindata["type"] == "register":
            self.status = "REGISTER"
        elif self._signindata["type"] == "message":
            if self._signindata["msg"] == "NO_AUTH":
                self.status = "AUTHORIZED"
                self.authorized = True
                print("Skycloud: Server authorized client without signin method.")
            else:
                self.status = "SIGNIN/MESSAGE"
                print(
                    f"Skycloud: Server responded with a unknown message upon requesting sign in methods:\n{self._signindata["msg"]}"
                )
        else:
            self.websocket.close(reason="INVALID_DATA")
            print(self._signindata)
            raise ConnectionError("Server sent invalid data for signin terminated.")

        self.keepalivethread.daemon = keepalive_daemon
        if keepalive:
            self.keepalivethread.start()

    def keepalive(self):
        while not self.killswitch:
            try:
                self.websocket.ping()
                time.sleep(5)  # Keepalive interval
            except Exception as e:
                print(f"Keepalive failed: {e}")
                self.killswitch = True  # Exit the loop if there's an error
                break


    def close(self):
        self.killswitch = True
        if self.keepalivethread.is_alive():
            self.keepalivethread.join()
        self.websocket.close()

    def _send(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        self.websocket.send(self.cipher.encrypt(data))

    def _recv(self):
        return self.cipher.decrypt(self.websocket.recv())

    def signin(self, user: str, password: str):
        if self.status == "REGISTER":
            raise RuntimeError("Server does not have any users registered. Please use the registeruser() method")
        if not "signin" in self.signin_methods:
            raise RuntimeError("Server does not support normal Sign in method")
    
    def registeruser(self, username: str, password: str):
        if self.status == "LOGIN":
            raise RuntimeError("Server is requesting a login.\nPlease use signin(), signin_key() methods depending if your self.signin_methods \ncontain \"signin\" for signin() and \"rsakey\" for signin_key()")
        
        self._send(json.dumps({"type":"register","username":username,"password":password}))
        
        json.loads(self._recv())

client = SkyCloudClient("127.0.0.1",keepalive=True)