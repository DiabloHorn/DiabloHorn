#CredentialScavenger - credsca
#DiabloHorn http://diablohorn.wordpress.com
import poplib
import socket

class Pop3:
    """Simple pop3 class to authenticate against server
    """   
    def __init__(self,pop3server,pop3port,ssl):
        self.pop3s = pop3server
        self.pop3p = pop3port
        self.ssl = ssl
        socket.setdefaulttimeout(50)
        
    def login(self,username,password):
        if self.ssl:
            self.mailserver = poplib.POP3_SSL(self.pop3s, self.pop3p)
        else:
            self.mailserver = poplib.POP3(self.pop3s, self.pop3p)    
        try:
            self.mailserver.user(username)
            self.mailserver.pass_(password)
        except:
            return
        return "OK"
        
    def logout(self):
        self.mailserver.quit()
        
    def checklogin(self,username,password):
        rc = self.login(username,password)
        if rc is not None:
            self.logout()
            return True
        self.logout()
        return False    
