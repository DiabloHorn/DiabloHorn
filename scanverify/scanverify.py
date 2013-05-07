#!/usr/bin/env python
#DiabloHorn http://diablohorn.wordpress.com

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
#{hash:{timestamp: (srchost, dsthost,port)}
connections = dict()

def usage():
    print 'DiabloHorn http://diablohorn.wordpress.com'
    print 'verify nmap scans, find delayed responses'
    print 'Usage: '
    print sys.argv[0] + ' <pcapfile> <threshold>'
    print 'Ex: '
    print sys.argv[0] + ' delayedresponse.pcap 0.8'
    print '[timestamp] [difference] [src ip] [dst ip] [dst port] [response flags]'
    print '1367887784.231386 5.00098395348 10.50.0.107 10.50.0.103 22 [\'SYN\', \'ACK\']'   
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
                connections[gethash(tohash)] = {packet.time:(packet[IP].src, packet[IP].dst,packet[TCP].dport)}
            #iffy...seems to work for now
            if humanflags[0] == 'RST' or (humanflagslen > 1 and humanflags[1] == 'ACK'):  
                tohash = '%s%s%s%s%s' % (packet[IP].dst, packet[IP].src, packet[TCP].dport, packet[TCP].sport, packet[TCP].ack-1)
                originalrequest = connections.get(gethash(tohash))
                if originalrequest != None:
                    originaltime = originalrequest.keys()[0]
                    #make sure we are dealing with a response to our initiated connection
                    if originalrequest[originaltime][0] == packet[IP].dst:
                        timediff = (packet.time - originaltime)
                        if timediff > threshold:
                            print '%.6f %s %s %s' % (originaltime, timediff, ' '.join([str(x) for x in originalrequest[originaltime]]), humanflags)
