#!/usr/bin/env python
#fw-dns
#POC to only allow certain dns queries
#prolly allready exists but it's good for knowledge development.
#DiabloHorn http://diablohorn.wordpress.com
#Thanks to the following sources:
#http://jon.oberheide.org/blog/2008/12/20/dpkt-tutorial-3-dns-spoofing/
#http://jon.oberheide.org/blog/2008/08/25/dpkt-tutorial-1-icmp-echo/
#http://code.activestate.com/recipes/491264-mini-fake-dns-server/
#http://docs.python.org/library/socket.html

#Functionality
# - = done
# x = todo
###
# - Queries can either be full domain(www.google.com), or only base domain(google.com)
# - Block queries
# - relays queries
# - reads settings from config
# - reloads config
#   - on/off using -auto
# - drops privileges
# - reload config on key combo
###

import socket
import sys
import os
import pwd
import ConfigParser
import exceptions
from RepeatTimer import RepeatTimer

udps = None
fudps = None

CONFIG_LOCATION = "fwdns.cfg"
DNS_SERVER = ("192.168.2.254",53)
IF_LISTEN = "127.0.0.1"

RELOAD_TIME = "12h"
ALLOWED_FULL_DOMAINS = []
ALLOWED_PARTIAL_DOMAINS = []

#get current uid, prolly root
privUID = os.geteuid()
#get low priv uid
normalUID = pwd.getpwnam('nobody')[2]

def configprint(serror=False):
    global DNS_SERVER
    global IF_LISTEN
    global RELOAD_TIME
    global ALLOWED_FULL_DOMAINS
    global ALLOWED_PARTIAL_DOMAINS
    if(serror):
        print "***CONFIG PARSE ERROR***"
    print "##############################################"    
    print "new configuration:"
    print "reload time:\n\t%s" % RELOAD_TIME
    print "dns server:\n\t%s" % str(DNS_SERVER)
    print "if listen:\n\t%s" % IF_LISTEN
    print "allowed full domains:\n\t%s" % str(ALLOWED_FULL_DOMAINS)
    print "allowed partial domains:\n\t%s" % str(ALLOWED_PARTIAL_DOMAINS)
    print "##############################################"
        
def parseconfig():
    global CONFIG_LOCATION
    global DNS_SERVER
    global IF_LISTEN
    global RELOAD_TIME
    global ALLOWED_FULL_DOMAINS
    global ALLOWED_PARTIAL_DOMAINS
    global cfgthread

    config = ConfigParser.SafeConfigParser()
    config.read(CONFIG_LOCATION)
    
    try:
        RELOAD_TIME = config.get("GLOBAL OPTIONS","reload_time")
        DNS_SERVER = (config.get("GLOBAL OPTIONS","dns_server"), 53)
        IF_LISTEN = config.get("GLOBAL OPTIONS","if_listen")
        ALLOWED_FULL_DOMAINS = config.get("ALLOWED DOMAINS","full").split(',')
        ALLOWED_PARTIAL_DOMAINS = config.get("ALLOWED DOMAINS","partial").split(',')
    except ConfigParser.NoSectionError, nse:
        print nse
    except ConfigParser.NoOptionError, noe:
        print noe
    except Exception, ex:
        print ex
        print "Startup using configured defaults"
        configprint(True)      
    configprint()
    
    
def sis():
    global fudps
    fudps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    fudps.bind(('',0))

def blis(bip):
    global udps    
    udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udps.bind((bip,53))

def getdomain(data):
    dns = dpkt.dns.DNS(data)
    if dns.qr != dpkt.dns.DNS_Q:
        return None
    if dns.opcode != dpkt.dns.DNS_QUERY:
        return None
    if len(dns.qd) != 1:
        return None
    if len(dns.an) != 0:
        return None
    if len(dns.ns) != 0:
        return None
    if dns.qd[0].cls != dpkt.dns.DNS_IN:
        return None
    if dns.qd[0].type != dpkt.dns.DNS_A:
        return None

    return dns.qd[0].name

def relay(data):
    global fudps
    fudps.sendto(data,DNS_SERVER)
    d, a = fudps.recvfrom(4096)
    return d #only return data section
        
def fw(data):
    global ALLOWED_DOMAINS
    reqdom = getdomain(data)
    if reqdom == None:
        print "Unrecognised packet DROP"
        return None
        
    if reqdom in ALLOWED_PARTIAL_DOMAINS:
        print "Forward Partial"
        return relay(data)
    else:
        for domain in ALLOWED_FULL_DOMAINS:
            if reqdom.endswith(domain):
                print "Forward Full: %s" % reqdom
                return relay(data)
            else:
                print "DROP"
                return None
    return None
    
if __name__ == "__main__":
    #initial config parsing
    parseconfig()
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "-auto":
            print "Automatic Config Loading Activated"
            cfgthread = RepeatTimer(float(RELOAD_TIME), parseconfig)
            cfgthread.start()    

    #append needed library
    sys.path.append("libs/dpkt-1.7/dpkt") 
    #try to import the library
    try:
        import dpkt
    except:
        print "Could not locate dpkt library"
        sys.exit()
    print "Starting fw-dns"
    #bind on localhost        
    blis(IF_LISTEN)
    print "Listening on localhost %s" % IF_LISTEN
    #connect to remote server
    sis()
    print "Connected to remote DNS server %s" % str(DNS_SERVER)
    os.seteuid(normalUID)
    print "Dropped privileges"

    while 1:
        try:
            data, addr = udps.recvfrom(4096)
            resp = fw(data)
            if resp != None:
                udps.sendto(resp,addr)
        except KeyboardInterrupt:
            choice = raw_input("Reload Config (r), Close (any key)?")
            if choice == "r":
                os.seteuid(privUID)
                parseconfig()
                os.seteuid(normalUID)
                pass
            else:
                print 'Closing'
                os.seteuid(privUID)
                udps.close()
                fudps.close()
                if len(sys.argv) > 1:
                    if sys.argv[1] == "-auto":
                        cfgthread.cancel()
                sys.exit()
        except Exception, ex:
            print "Ooops!, check src: %s" % ex
            sys.exit()
    
    
