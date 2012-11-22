#CredentialScavenger - credsca
#DiabloHorn http://diablohorn.wordpress.com
import sqlite3
import os
import time

class Database:
    """Simple database class to insert, delete entries and create the database
    """
    
    def __init__(self):
        self.dbconn = None
        self.dbcur = None
  
    def openconn(self,dbname):
        if self.dbconn == None or self.dbcur == None:
            self.dbconn = sqlite3.connect(dbname)
            self.dbcur = self.dbconn.cursor()
        
    def close(self):
        self.dbconn.close()        
      
    def createcredstable(self):
        self.dbcur.execute("CREATE TABLE creds (username TEXT NOT NULL,password TEXT NOT NULL,proto TEXT NOT NULL, module TEXT NOT NULL, date INTEGER NOT NULL, CHECK(username <> ''),CHECK(password <> ''))")
        self.dbconn.commit()

    def insertcreds(self,username,password,proto,module):
        self.dbcur.execute("INSERT OR REPLACE INTO creds VALUES (?,?,?,?,?)",(username,password,proto,module,int(time.time())))
        self.dbconn.commit()
