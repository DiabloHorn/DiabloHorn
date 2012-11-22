#CredentialScavenger - credsca
#DiabloHorn http://diablohorn.wordpress.com
import sys
sys.path.append("../")
from credcheck import imap
from credcheck import pop3

class Gmail:

    _imapgmail = 'imap.gmail.com'
    _imapport = '993'
    _imapssl = 'True'

    _pop3gmail = 'pop.gmail.com'
    _pop3port = '995'
    _pop3ssl = 'True'

    _domain = '@gmail.com'
    
    def __init__(self):
        self.pop3 = pop3.Pop3(Gmail._pop3gmail,Gmail._pop3port,Gmail._pop3ssl)
        self.imap = imap.Imap(Gmail._imapgmail,Gmail._imapport,Gmail._imapssl)

    def prepareusername(self,username):
        luser = username.lower()
        if Gmail._domain in luser:
            return luser
        else:
            if '@' in luser:
                return luser.split('@',1)[0] + Gmail._domain
            else:
                return luser + Gmail._domain

    def checklogin(self,username,password):
        gmailusername = self.prepareusername(username)
        if self.imap.checklogin(gmailusername,password):
            return [gmailusername,password,'imap']
        elif self.pop3.checklogin(gmailusername,password): 
            return [gmailusername,password,'pop3']
