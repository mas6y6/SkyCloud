import json
import threading
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from websockets.sync.client import connect
import logging

class SkyCloudClient:
    def __init__(self,host,port=3127,ssl=None):
        if ssl == None:
            self.uri = f"ws://{host}:{port}"
        else:
            self.uri = f"wss://{host}:{port}"
        
        self.websocket = connect(self.uri,ssl=ssl)
        # Receive initial handshake
        handshake = json.loads(self.websocket.recv())
        print(f"Handshake received: Version {handshake['version']}, MOTD: {handshake['motd']}")

        # Receive public key
        public_key_message = self.websocket.recv()
        public_key_data = json.loads(public_key_message)
        server_public_key = serialization.load_pem_public_key(public_key_data['key'].encode())

        # Generate symmetric key and send encrypted key
        symmetric_key = Fernet.generate_key()
        self.cipher = Fernet(symmetric_key)
        encrypted_symmetric_key = server_public_key.encrypt(
            symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        self.websocket.send(encrypted_symmetric_key)

        # Send encryption test
        self._send(json.dumps({"type": "encryption_test", "msg": "test"}))
        print("Sent encryption test")

        # Receive and verify encryption test response
        response = self._recv()
        if response["type"] == "encryption_test" and response["msg"] == "success!":
            print("Encryption test passed. Connection established.")
        else:
            raise ValueError("Encryption test failed!")
        
    def _send(self,data):
        self.websocket.send(self.cipher.encrypt(data))
        
    def _recv(self):
        return self.cipher.decrypt(self.websocket.recv())
        
client = SkyCloudClient("localhost")
