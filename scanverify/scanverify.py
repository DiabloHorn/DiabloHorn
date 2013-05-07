#!/usr/bin/env python

import sys
import md5

#http://stackoverflow.com/questions/13249341/surpress-scapy-warning-message-when-importing-the-module
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

try:
    #use this if the other line doesn't work
    #from scapy import *
    from scapy.all import *
except:
    print 'You need to install python-scapy'
    sys.exit()

conf.verb = 0
#{hash:{timestamp: (host,port)}
connections = dict()

def usage():
    print 'DiabloHorn http://diablohorn.wordpress.com'
    print 'verify nmap scans, find delayed responses'
    print 'Usage: '
    print sys.argv[0] + ' <pcapfile> <threshold>'
    print 'Ex: '
    print sys.argv[0] + ' nmapscan.pcap 0.8'
    print '[timestamp] [difference] [dst ip] [dst port]'
    print '1367779878.16 5.00033688545 10.50.0.103 22'
    print '1367779879.26 5.00119495392 10.50.0.103 22'
    
    sys.exit()

def flags2human(flagbits):
    flags = {0:"FIN",1:"SYN",2:"RST",3:"PUSH",4:"ACK",5:"URG",6:"ECN-echo",7:"CWR",8:"ECN-nonce"}
    output = []
 
    for x in range(0,8):
        if (flagbits >> x) & 1:
            output.append(flags[x])  
 
    return output

def gethash(data):
    return md5.new(data).hexdigest()
   
if __name__ == "__main__":
    if len(sys.argv) != 3:
        usage()
       
    #should enable us to read large files        
    pcapdata = PcapReader(sys.argv[1])
    threshold = float(sys.argv[2])

    for packet in pcapdata:
        if packet.haslayer(TCP):
            humanflags = flags2human(packet[TCP].flags)
            humanflagslen = len(humanflags)
            if humanflags[0] == 'SYN' and humanflagslen == 1:
                tohash = '%s%s%s%s%s' % (packet[IP].src, packet[IP].dst, packet[TCP].sport, packet[TCP].dport, packet[TCP].seq)
                connections[gethash(tohash)] = {packet.time:(packet[IP].dst,packet[TCP].dport)}
            #iffy...seems to work for now
            if humanflagslen > 1 and humanflags[1] == 'ACK':  
                tohash = '%s%s%s%s%s' % (packet[IP].dst, packet[IP].src, packet[TCP].dport, packet[TCP].sport, packet[TCP].ack-1)
                originalrequest = connections.get(gethash(tohash))
                if originalrequest != None:
                    originaltime = originalrequest.keys()[0]
                    timediff = (packet.time - originaltime)
                    if timediff > threshold:
                        print '%.6f %s %s' % (originaltime, timediff, ' '.join([str(x) for x in originalrequest[originaltime]]))
