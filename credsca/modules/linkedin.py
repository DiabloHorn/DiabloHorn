#CredentialScavenger - credsca
#DiabloHorn http://diablohorn.wordpress.com
import sys
sys.path.append("../")
from credcheck import httpform

class Linkedin:

    _baseformurl = 'https://www.linkedin.com'
    _loginformurl = _baseformurl + '/uas/login'
    
    def __init__(self):
        self.httpform = httpform.Httpform()
        
    def login(self,username,password):
        loginform = self.httpform.getform(Linkedin._loginformurl,'login')
        posturl = Linkedin._baseformurl + loginform.pop('action')
        loginform['session_key'] = username
        loginform['session_password'] = password                
        res = self.httpform.requestpage(posturl,loginform) 
        if 'Welcome! | LinkedIn' in res:
            self.logouturl = self.httpform.getlogout(res,'Sign Out')
            return "OK"
        else:
            return "NOK"
        
    def logout(self):
        if self.logouturl is not None:
            self.httpform.requestpage(self.logouturl)
           
    def checklogin(self,username,password):
        rc = self.login(username,password)
        if rc == "OK":
            self.logout()
            return [username,password,'httpform']
    
