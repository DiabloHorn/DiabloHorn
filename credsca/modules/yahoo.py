#CredentialScavenger - credsca
#DiabloHorn http://diablohorn.wordpress.com
import sys
sys.path.append("../")
from credcheck import imap
from credcheck import pop3

class Yahoo:

    _imapyahoo = 'imap.mail.yahoo.com'
    _imapport = '993'
    _imapssl = 'True'

    _pop3yahoo = 'pop.mail.yahoo.com'
    _pop3port = '995'
    _pop3ssl = 'True'

    _domain = '@yahoo.com'
    
    def __init__(self):
        self.pop3 = pop3.Pop3(Yahoo._pop3yahoo,Yahoo._pop3port,Yahoo._pop3ssl)
        self.imap = imap.Imap(Yahoo._imapyahoo,Yahoo._imapport,Yahoo._imapssl)

    def prepareusername(self,username):
        luser = username.lower()
        if Yahoo._domain in luser:
            return luser
        else:
            if '@' in luser:
                return luser.split('@',1)[0] + Yahoo._domain
            else:
                return luser + Yahoo._domain

    def checklogin(self,username,password):
        yahoousername = self.prepareusername(username)
        if self.imap.checklogin(yahoousername,password):
            return [yahoousername,password,'imap']
        elif self.pop3.checklogin(yahoousername,password): 
            return [yahoousername,password,'pop3']
