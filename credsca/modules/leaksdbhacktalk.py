#CredentialScavenger - credsca
#DiabloHorn http://diablohorn.wordpress.com
import sys
sys.path.append("../")
from credcheck import httpform

class Leaksdbhacktalk:

    _baseformurl = 'http://leaks-db.hacktalk.net'
    _loginformurl = _baseformurl + '/node?destination=node'
    
    def __init__(self):
        self.httpform = httpform.Httpform()
        
    def prepareusername(self,username):
        luser = username.lower()
        if '@' in luser:
            return luser.split('@',1)[0]
        else:
            return luser
                
    def login(self,username,password):
        loginform = self.httpform.getformbyid(Leaksdbhacktalk._loginformurl,'user-login-form')
        posturl = Leaksdbhacktalk._baseformurl + loginform.pop('action')
        loginform['name'] = username
        loginform['pass'] = password                
        res = self.httpform.requestpage(posturl,loginform) 
        if 'My account' in res:
            self.logouturl = Leaksdbhacktalk._baseformurl + self.httpform.getlogout(res,'Log out')
            return "OK"
        else:
            return "NOK"
        
    def logout(self):
        if self.logouturl is not None:
            self.httpform.requestpage(self.logouturl)
           
    def checklogin(self,username,password):
        htuser = self.prepareusername(username)
        rc = self.login(htuser,password)
        if rc == "OK":
            self.logout()
            return [htuser,password,'httpform']
    
