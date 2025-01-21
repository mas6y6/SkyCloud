import bcrypt
import uuid
import sqlite3
import threading
import time
import logging
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from .permissions import Permissions, PERMISSIONS


class Session:
    def __init__(self, username, time, sessionid, usernameid, permissions: Permissions, websocket):
        self.username = username
        self.usernameid = usernameid
        self.time = time
        self.sessionuuid = sessionid
        self.permissions = permissions
        self.alive = True
        self.websocket = websocket

    def tick(self):
        if self.time == 1:
            self.alive = False
        else:
            self.time -= 1

    def renew(self):
        self.time = 3600


class AuthHandler:
    def __init__(self, conn: sqlite3.Connection):
        self.logger = logging.getLogger("AuthHandler")
        self.sessions = {}
        self.logger.info("Initializing SkyCloud AuthHandler")

        self.conn = conn

        try:
            cursor = self.conn.cursor()
            cursor.execute(
                """
            CREATE TABLE IF NOT EXISTS users (
                uuid TEXT UNIQUE NOT NULL PRIMARY KEY,
                username TEXT NOT NULL,
                password TEXT,
                public_key TEXT,
                permissions INT NOT NULL
            )
            """
            )
        except Exception as e:
            self.logger.error(f"Error creating table: {e}")

        self.conn.commit()
        self.logger.info("SkyCloud AuthHandler ready")

    def user_exists(self, username):
        cursor = self.conn.cursor()
        cursor.execute("SELECT 1 FROM users WHERE username = ?", (username,))
        return cursor.fetchone() is not None

    def register_user(
        self, username, password=None, public_key=None, permissions=Permissions(4), websocket=None
    ):
        if self.user_exists(username):
            self.logger.warning(
                f'Attempted to register user "{username}" that already exists.'
            )
            return None

        hashed_password = (
            bcrypt.hashpw(password.encode(), bcrypt.gensalt()) if password else None
        )
        new_uuid = str(uuid.uuid4())

        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT INTO users (uuid, username, password, public_key, permissions) VALUES (?, ?, ?, ?, ?)",
            (new_uuid, username, hashed_password, public_key, permissions.bitfield),
        )
        self.conn.commit()

        self.logger.info(f'Registered a new user "{username}" {new_uuid} with permission bitfield {permissions.bitfield}')
        
        return self._create_session(new_uuid,websocket)

    def login_user(self, username, password=None, key=None, websocket=None):
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT password, public_key, uuid FROM users WHERE username = ?",
            (username,),
        )
        result = cursor.fetchone()

        if result is None:
            self.logger.warning("User attempted to login with invalid username")
            return False

        stored_password, stored_key, userid = result

        if (
            password
            and stored_password
            and bcrypt.checkpw(password.encode(), stored_password)
        ):
            return self._create_session(username,websocket)
        elif key and stored_key:
            public_key = serialization.load_pem_public_key(stored_key.encode())
            try:
                public_key.verify(
                    key,
                    b"authentication challenge",
                    padding.PKCS1v15(),
                    hashes.SHA256(),
                )
                return self._create_session(userid,websocket)
            except Exception as e:
                self.logger.warning("Invalid key used for login")
                return None
        else:
            self.logger.warning("User attempted to login with invalid credentials")
            return None

    def _create_session(self, useruuid, websocket):
        sessionuuid = str(uuid.uuid4())
        cursor = self.conn.cursor()
        cursor.excute(
            "SELECT username, uuid, permissions FROM users WHERE uuid = ?", (useruuid)
        )
        userdata = cursor.fetchone()
        username, user_uuid, permissions = userdata

        perm = Permissions(permissions)

        self.sessions[sessionuuid] = Session(
            username=username,
            time=3600,
            sessionid=sessionuuid,
            usernameid=user_uuid,
            permissions=perm,
            websocket=websocket
        )
        self.logger.info(
            f'Opened new session for user "{useruuid}" under uuid "{sessionuuid}"'
        )
        return self.sessions[sessionuuid]

    def is_empty(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users")
        count = cursor.fetchone()[0]
        return count == 0

    def registerkey(self, key, username):
        if not self.user_exists(username):
            self.logger.warning(
                f'Attempted to use a key for non-existent user "{username}".'
            )
            return False

        cursor = self.conn.cursor()

        # Save the public key in the database for the user
        public_key = key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

        cursor.execute(
            "UPDATE users SET public_key = ? WHERE username = ?", (public_key, username)
        )
        self.conn.commit()
        self.logger.info(f'Public key registered for user "{username}"')
        return True

    def __del__(self):
        self.conn.close()

    def close(self):
        self.conn.close()
