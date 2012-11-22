#CredentialScavenger - credsca
#DiabloHorn http://diablohorn.wordpress.com
import imaplib
import socket

class Imap:
    """Simple imap class to authenticate against server
    """
    def __init__(self,imapserver,imapport,ssl):
        self.ims = imapserver
        self.imp = imapport
        self.ssl = ssl
        socket.setdefaulttimeout(50)
        
    def login(self,username,password):
        if self.ssl:
            self.mailserver = imaplib.IMAP4_SSL(self.ims, self.imp)
        else:
            self.mailserver = imaplib.IMAP4(self.ims, self.imp)
        try:
            rc, resp = self.mailserver.login(username, password)
        except: 
            return
        return rc
        
    def logout(self):
        self.mailserver.logout()       
        
    def checklogin(self,username,password):
        rc = self.login(username,password)
        if rc is not None:
            self.logout()
            return True
        return False
    
