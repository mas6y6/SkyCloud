import bcrypt
import uuid
import sqlite3
import threading
import time
import logging
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

class Session:
    def __init__(self,username,time,sessionid):
        self.username = username
        self.time = time
        self.uuid = sessionid
        
    def tick(self):
        self.time -= 1
    
    def renew(self):
        self.time = 3600

class AuthHandler:
    def __init__(self, conn):
        self.logger = logging.getLogger("AuthHandler")
        self.sessions = {}
        self.logger.info("Initializing SkyCloud AuthHandler")

        self.conn = conn
        self.cursor = self.conn.cursor()

        try:
            self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                uuid TEXT UNIQUE NOT NULL,
                username TEXT NOT NULL,
                password TEXT,
                public_key TEXT
            )
            ''')
        except Exception as e:
            self.logger.error(f"Error creating table: {e}")

        self.conn.commit()
        self.logger.info("SkyCloud AuthHandler ready")
        self.sessionlogger = logging.getLogger("SessionHandler")

        threading.Thread(target=self.sessionhandler, daemon=True).start()

    def sessionhandler(self):
        self.sessionlogger.info("Started Session Handler")
        while True:
            expired_sessions = [i for i, session in self.sessions.items() if session.time < 1]
            for i in expired_sessions:
                self.sessions.pop(i)
                self.sessionlogger.info(f"Session {i} expired")
            time.sleep(1)

    def user_exists(self, username):
        self.cursor.execute('SELECT 1 FROM users WHERE username = ?', (username,))
        return self.cursor.fetchone() is not None

    def register_user(self, username, password=None, public_key=None):
        if self.user_exists(username):
            self.logger.warning(f"Attempted to register user \"{username}\" that already exists.")
            return False

        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()) if password else None
        new_uuid = str(uuid.uuid4())

        self.cursor.execute(
            'INSERT INTO users (uuid, username, password, public_key) VALUES (?, ?, ?, ?)',
            (new_uuid, username, hashed_password, public_key)
        )
        self.conn.commit()

        self.logger.info(f"Registered new user \"{username}\" {new_uuid}")
        return True

    def login_user(self, username, password=None, key=None):
        self.cursor.execute('SELECT password, public_key FROM users WHERE username = ?', (username,))
        result = self.cursor.fetchone()

        if result is None:
            self.logger.warning("User attempted to login with invalid username")
            return False

        stored_password, stored_key = result

        if password and stored_password and bcrypt.checkpw(password.encode(), stored_password):
            return self._create_session(username)
        elif key and stored_key:
            public_key = serialization.load_pem_public_key(stored_key.encode())
            try:
                public_key.verify(
                    key,
                    b"authentication challenge",
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
                return self._create_session(username)
            except Exception as e:
                self.logger.warning("Invalid key used for login")
                return None
        else:
            self.logger.warning("User attempted to login with invalid credentials")
            return None

    def _create_session(self, username):
        sessionuuid = str(uuid.uuid4())
        self.sessions[sessionuuid] = Session(username, 3600, sessionuuid)
        self.logger.info(f"Opened new session for user \"{username}\" under uuid \"{sessionuuid}\"")
        return self.sessions[sessionuuid]

    def is_empty(self):
        cursor = self.conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM users')
        count = cursor.fetchone()[0]
        return count == 0

    def registerkey(self, key, username):
        if not self.user_exists(username):
            self.logger.warning(f"Attempted to use a key for non-existent user \"{username}\".")
            return False

        # Save the public key in the database for the user
        public_key = key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        self.cursor.execute(
            'UPDATE users SET public_key = ? WHERE username = ?',
            (public_key, username)
        )
        self.conn.commit()
        self.logger.info(f"Public key registered for user \"{username}\"")
        return True

    def __del__(self):
        self.conn.close()

    def close(self):
        self.conn.close()