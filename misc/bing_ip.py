#!/usr/bin/env python
#Use BING to search for websites hosted on a ip address and return the current ip they have
#Author: DiabloHorn (http://diablohorn.wordpress.com)

#Working with the bing engine
#example url: http://api.bing.net/xml.aspx?AppId=<APPID>&Version=2.2&Query=ip:74.207.254.18&Sources=web&web.count=50&web.offset=0
#example usage: nmap -vv -n -sL 74.207.254.15-20 | grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' | ./bing_ip.py -a <APPID> -f

import sys
import getopt
import urllib2
from xml.dom.minidom import parse, parseString
from urlparse import urlparse
import socket

class bing():
    _appid = ""
    _url = "http://api.bing.net/xml.aspx?"
    _urlparams = {"appid":"","version":"2.2","query":"","sources":"web","web.count":"50","web.offset":"0"}
    _foundurls = {}
    _totalres = 0
    
    def _constructurl(self):
        queryurl = self._url
        for k,v in self._urlparams.iteritems():
            if queryurl[-1] == "?":
                queryurl = queryurl + k + "=" + v
            else:
                queryurl = queryurl + "&" + k + "=" + v
        return queryurl
    
    def __init__(self,appid):
        self._urlparams.update({"appid":appid})
        
    def _fetchresult(self,bingurl):
        con = urllib2.urlopen(bingurl)
        content = con.read()
        con.close()
        return content
        
    def _query(self,qry,offset=0):
        self._urlparams.update({"query":qry,"web.offset":str(offset)})
        return self._fetchresult(self._constructurl())
    
    def _getUrls(self,bingdata,uptotal=False):
        dom = parseString(bingdata)
        if(uptotal):
            self._totalres = dom.getElementsByTagName("web:Total")[0].firstChild.data.encode('utf8')    
        weburls = dom.getElementsByTagName("web:Url")
        for url in weburls:
            host = urlparse(url.firstChild.data.encode('utf8')).netloc
            try:
                self._foundurls[host] = socket.gethostbyname(host)
            except:
                self._foundurls[host] = ""
                        
    def IPQuery(self,qry):
        self._foundurls.clear()
        self._getUrls(self._query("ip:"+qry),True)
        print "[*] Found Results(" + qry + "): " + self._totalres
        pages = int(self._totalres) / 50
        print "[*] Pages: " + str(pages)
        for i in range (0,pages):
            self._getUrls(self._query("ip:"+qry,(i+1)))
        return self._foundurls

def txthelp():
    print "[*] DiabloHorn http://diablohorn.wordpress.com"
    print "[*] Use BING to search for websites hosted on a ip address"
    print "[*] " + sys.argv[0] + " -a <appid> -i <ip> [-f <ipfile list>]"
    print "[*] -a BING appid"
    print "[*] -i ip address to use"
    print "[*] -f read file from stdin(ex: cat ips.txt | " + sys.argv[0] 
    print "[*] -h this help" 


    
#main :)
if __name__ == "__main__":
    if len(sys.argv) <=2:
        txthelp()
        sys.exit(0)
    
    targetscan = ""
    fromfile = False
    bingkey = ""
        
    try:
        opts, args = getopt.getopt(sys.argv[1:],"a:i:fh",["appid","ip","ipfile","help"])
    except getopt.GetoptError, err:
        print str(err)
        sys.exit(0)

    for o,a in opts:
        if o == "-h":
            txthelp()
            sys.exit(0)            
        elif o == "-v": 
            verbose = True
        elif o == "-a":
            bingkey = a            
        elif o == "-i":
            targetscan = a
        elif o == "-f":
            fromfile = True
        else:
            txthelp()
            sys.exit(0)

    bip = bing(bingkey)
    if fromfile:
        for line in sys.stdin:
            for k,v in bip.IPQuery(line.strip()).iteritems():
                print k+":"+v
    else:
        for k,v in bip.IPQuery(targetscan).iteritems():
            print k+":"+v
