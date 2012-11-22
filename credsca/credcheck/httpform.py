#CredentialScavenger - credsca
#DiabloHorn http://diablohorn.wordpress.com
#Excellent example of beautifulsoup and login to a website
#   http://yuji.wordpress.com/tag/beautifulsoup/

from bs4 import BeautifulSoup
import urllib2,urllib
from urlparse import urlparse
import socket

class Httpform:
    """Simple http class to provide basic authentication for html forms
    """
    def __init__(self):
#        use when in need of debugging, make sure you have an intercepting proxy ready    
#        proxy_handler = urllib2.ProxyHandler({'https': 'http://127.0.0.1:8080/'})
#        self.opener = urllib2.build_opener(proxy_handler,urllib2.HTTPCookieProcessor())
        socket.setdefaulttimeout(50)
        self.opener = urllib2.build_opener(urllib2.HTTPCookieProcessor())            
        urllib2.install_opener(self.opener)
        
    
    def requestpage(self,requrl,data=None):
        """request a desired page and return the html content"""
        if data is not None:
            encodedparams = urllib.urlencode(data)
            res = self.opener.open(requrl,encodedparams).read()
        else:
            res = self.opener.open(requrl).read()
        self.opener.close()
        return res
            
    def getform(self,loginformurl,formname):
        """retun all fields of an specified form in a dict"""
        self.finalform = dict()
        soup = BeautifulSoup(self.requestpage(loginformurl))
        loginform = soup.find('form',attrs={'name': formname})
        self.finalform['action'] = loginform['action']
        inputs = loginform.find_all('input')        
        for i in inputs:
            try:
                self.finalform[i['name']] = i['value']
            except KeyError:
                self.finalform[i['name']] = ""
        return self.finalform
        
    def getformbyid(self,loginformurl,formname):
        """retun all fields of an specified form in a dict"""
        self.finalform = dict()
        soup = BeautifulSoup(self.requestpage(loginformurl))
        loginform = soup.find('form',attrs={'id': formname})
        self.finalform['action'] = loginform['action']
        inputs = loginform.find_all('input')      
        for i in inputs:
            try:
                self.finalform[i['name']] = i['value']
            except KeyError:
                self.finalform[i['name']] = ""
        return self.finalform        
    
    def addheaders(self):
        #todo
        pass  
                      
      
    def getlogout(self,pagehtml,linkname):
        """get a link with the specified name"""
        soup = BeautifulSoup(pagehtml)        
        links = soup.find_all('a')
        for i in links:
            if linkname in i:
                return i['href']
                
