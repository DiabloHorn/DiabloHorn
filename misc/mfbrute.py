#!/usr/bin/env python
# mod_negotiation file bruteforce
#Author: DiabloHorn

import string
import sys
import getopt
import httplib
import re


def txthelp():
    print "[*] DiabloHorn http://diablohorn.wordpress.com"
    print "[*] Mod Negotiate File Brute Force"
    print "[*] " + sys.argv[0] + " -t <target> -d <dir list> -f <file list> [-v]"
    print "[*] -t target to scan"
    print "[*] -d directories which will be scanned" 
    print "[*] -f files which will be scanned" 
    print "[*] -v verbose" 
    print "[*] -h this help" 

#dirty regex way to parse response items in the alternates header
def parsehdrdata(hdr,rl):
    if hdr == None:
        return
    
    foundfiles = dict()    
    m = re.findall('"(.+?)"',hdr)
    for a in m:
        if a not in foundfiles:
            foundfiles[a] = rl
    if verbose:
        for k,v in foundfiles.iteritems():
            print string.join([v,k],'')         
    return foundfiles

#main :)
if __name__ == "__main__":
    if len(sys.argv) <=1:
        txthelp()
        sys.exit(0)

    verbose = False
    dirfile = None
    filefile = None
    targetscan = None

    try:
        opts, args = getopt.getopt(sys.argv[1:],"t:d:f:vh")
    except getopt.GetoptError, err:
        print str(err)
        sys.exit(0)

    for o,a in opts:
        if o == "-h":
            txthelp()
            sys.exit(0)            
        elif o == "-v": 
            verbose = True
        elif o == "-t":
            targetscan = a
        elif o == "-d":
            dirfile = a
        elif o == "-f":
            filefile = a
        else:
            txthelp()
            sys.exit(0)
    #read all dirs into memory, yeah this will hog your computer if it's a large list.
    bdir = []
    df = open(dirfile)
    try:
        for line in df:
            line = line.rstrip()
            if line.endswith("/"):
                bdir.append(line)
            else:
                bdir.append(line + "/")
    finally:
        df.close()

    httpheaders = {"Host":targetscan,"Accept":"a/b","User-Agent":"Googlebot-Image/1.0"}
    conn = httplib.HTTPConnection(targetscan)
    print "[*] Target set to: " + targetscan
    ff = open(filefile)
    try:
        for d in bdir:
            print "[*] Scanning: " + d
            ebresults = []
            ff.seek(0)
            for line in ff:
                line = line.rstrip()
                reqline = d +  line
                if verbose:
                    print "[*] Testing: " + reqline
                conn.request("GET",reqline,headers=httpheaders)
                r2 = conn.getresponse()
                r2.read()
                tempparseresult = parsehdrdata(r2.getheader("Alternates"),d)
                if None != tempparseresult:
                    ebresults.append(tempparseresult)
                r2 = None
            for ebresult in ebresults:
                for k,v in ebresult.iteritems():
                    print string.join([v,k],'')
    finally:
        ff.close()       
        conn.close() 
