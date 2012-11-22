#CredentialScavenger - credsca
#DiabloHorn http://diablohorn.wordpress.com
import sys
sys.path.append("../")
from credcheck import imap
from credcheck import pop3

class Hotmail:

    _pop3hotmail = 'pop3.live.com'
    _pop3port = '995'
    _pop3ssl = 'True'

    _domains = ['@hotmail.com','@live.com']
    
    def __init__(self):
        self.pop3 = pop3.Pop3(Hotmail._pop3hotmail,Hotmail._pop3port,Hotmail._pop3ssl)

    def prepareusername(self,username):
        luser = username.lower()
        users = list()
        for domain in Hotmail._domains:
            if '@' in luser:
                users.append(luser.split('@',1)[0] + domain)
            else:
                users.append(luser + domain)
        return users

    def checklogin(self,username,password):
        usernames = self.prepareusername(username)
        for u in usernames:
            if self.pop3.checklogin(u,password):
                return [u,password,'pop3']
