import json
import threading
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from websockets.sync.client import connect

def client_handler(uri):
    with connect(uri) as websocket:
        # Step 1: Receive the server's public RSA key
        public_key_message = websocket.recv()
        public_key_data = json.loads(public_key_message)
        server_public_key = serialization.load_pem_public_key(public_key_data['key'].encode())

        # Step 2: Generate a symmetric Fernet key
        symmetric_key = Fernet.generate_key()
        cipher = Fernet(symmetric_key)

        # Step 3: Encrypt the symmetric key using the server's public key
        encrypted_symmetric_key = server_public_key.encrypt(
            symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Step 4: Send the encrypted symmetric key to the server
        websocket.send(encrypted_symmetric_key)

        # Step 5: Receive and decrypt the handshake message from the server
        encrypted_message = websocket.recv()
        decrypted_message = cipher.decrypt(encrypted_message)
        print(f"Decrypted server message: {decrypted_message.decode()}")

def run_client():
    """Thread function to run the client."""
    print("Starting client...")
    client_handler("ws://localhost:8765")

if __name__ == "__main__":
    # Create a thread to run the client
    client_thread = threading.Thread(target=run_client)
    client_thread.start()

    # Main thread can perform other tasks here if needed
    print("Main thread is free to do other tasks while the client runs in the background.")

    # Optionally join the thread to wait for it to complete
    client_thread.join()
