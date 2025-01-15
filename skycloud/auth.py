import sqlite3, bcrypt, logging, uuid, threading, time

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
    def __init__(self,path):
        self.path = path
        self.logger = logging.getLogger("AuthHandler")
        self.sessions = {}
        self.logger.info("Initializing SkyCloud AuthHandler")
        
        self.conn = sqlite3.connect(self.path)
        self.cursor = self.conn.cursor()

        try:
            self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                uuid TEXT UNIQUE NOT NULL,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
            )
            ''')
        except:
            pass
        
        self.conn.commit()
        self.logger.info("SkyCloud AuthHandler ready")
        self.sessionlogger = logging.getLogger("SessionHandler")
        
        threading.Thread(target=self.sessionhandler).start()
        
    def sessionhandler(self):
        self.sessionlogger.info("Started Session Handler")
        while True:
            for i in self.sessions:
                if self.sessions.time < 1:
                    self.sessions.pop(i)
                    self.sessionlogger.info(f"Session {i} expired")
                else:
                    self.sessions[i].tick()
            time.sleep(1)
        
    def user_exists(self,user_uuid):
        self.cursor.execute('SELECT 1 FROM users WHERE uuid = ?', (user_uuid,))
        return self.cursor.fetchone() is not None

    def register_user(self, username, password):
        if self.user_exists(username):
            self.logger.warning(f"Attempted to register user \"{username}\" that already exists.")
            return False
        
        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        new_uuid = str(uuid.uuid4())
        
        self.cursor.execute('INSERT INTO users (uuid, username, password) VALUES (?, ?, ?)', (new_uuid, username, hashed_password))
        self.conn.commit()
        
        self.logger.info(f"Registered new user \"{username}\" {new_uuid}")
        return True
    
    def login_user(self, username, password):
        self.cursor.execute('SELECT password FROM users WHERE username = ?', (username,))
        result = self.cursor.fetchone()
        
        if result is None:
            self.logger.warning("User attempted to login with invalid username")
            return False
        
        hashed_password = result[0]
        
        if bcrypt.checkpw(password.encode(), hashed_password):
            sessionuuid = str(uuid.uuid4())
            self.sessions[sessionuuid] = Session(username, 3600, sessionuuid)
            self.logger.info(f"Opened new session for user \"{username}\" under uuid \"{sessionuuid}\"")
            
            self.logger.info(f"Login Successful for \"{username}\"")
            return self.sessions[sessionuuid]
        else:
            self.logger.warning("User attempted to login with invalid password")
            return None # Invalid password