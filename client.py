import json
import threading
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from websockets.sync.client import connect
from skycloud.permissions import Permissions, PERMISSIONS

class SkyCloudClient:
    def __init__(
        self, host, port=3127, ssl=None
    ):
        if ssl == None:
            self.uri = f"ws://{host}:{port}"
        else:
            self.uri = f"wss://{host}:{port}"

        self.status = "CONNECTING"
        self.killswitch = False
        self.authorized = False
        self.signin_methods = []
        self.compression = False
        
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
        
        self._send(json.dumps({"type":"signin/signin","username":user,"password":password}))
        
        auth = json.loads(self._recv())
        if auth["type"] == "auth":
            self.status = "AUTHORIZED"
            self.authorized = True
            self.sessionid = auth["sessionid"]
            return self.sessionid
        elif auth["type"] == "msg" and auth["message"] == "INVALID_CREDENTIALS":
            raise ValueError("Invalid credentials")
        else:
            raise ValueError(f"Server responded with an unknown message: {auth}")
    
    def registeruser(self, username: str, password: str, permissions: Permissions):
        if self.status == "LOGIN":
            raise RuntimeError("Server is requesting a login.\nPlease use signin(), signin_key() methods depending if your self.signin_methods \ncontain \"signin\" for signin() and \"rsakey\" for signin_key()")
        
        self._send(json.dumps({"type":"register","username":username,"password":password,"permissions":permissions.bitfield}))
        
        auth = json.loads(self._recv())
        if auth["type"] == "auth":
            self.status = "AUTHORIZED"
            self.authorized = True
            self.sessionid = auth["sessionid"]
            return self.sessionid
        else:
            raise ValueError(f"Server responded with an unknown message: {auth}")
    
    def close(self):
        self.websocket.close()

client = SkyCloudClient("127.0.0.1")
#client.registeruser("test","test",Permissions(4))
client.signin("test","test")
time.sleep(10)
client.close()