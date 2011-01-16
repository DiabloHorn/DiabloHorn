#!/usr/bin/env python

#author: DiabloHorn http://diablohorn.wordpress.com
#source ports borrowed from: http://nmap.org/book/man-bypass-firewalls-ids.html
#destination ports, just the ones I find interesting
#nice scapy reference material:
#   - http://www.secdev.org/projects/scapy/doc/usage.html
#   - http://www.secdev.org/conf/scapy_pacsec05.pdf
#   - https://cs.uwindsor.ca/~rfortier/CRIPT/uploads/slides/Python_Scapy.pdf


import sys
from scapy import *
#uncomment the line below and comment the one above if the script errors out
#from scapy.all import *

def txthelp():
    print
    print "Source Port Scanner"
    print "DiabloHorn - http://diablohorn.wordpress.com"
    print "Scans some hardcoded ports, from different sourceports"
    print "Usage: " + sys.argv[0] + " target"
    print "ATTENTION: Changing the amount of ports might hog a lot of memory and make it die"
    print
    
def flags2human(flagbits):
    flags = {0:"FIN",1:"SYN",2:"RST",3:"PUSH",4:"ACK",5:"URG",6:"ECN-Echo",7:"CWR"}
    output = []

    for x in range(0,8):
        if (flagbits >> x) & 1:
            output.append(flags[x])  

    return str(output)
    
if __name__ == "__main__":
    if len(sys.argv) <= 1:
        txthelp()
        sys.exit(1)
        
    ip = IP(dst=sys.argv[1])
    resultscan = []
    
    tcp = TCP(dport=[21,22,23,80,443,3389,5900,8080,8443],sport=[20,53,67,88],flags="S")
    ans,unans = sr(ip/tcp,timeout=2)
    for sent,rcvd in ans:
        if rcvd.haslayer(TCP):
            co = "%d,%d,%d,%s" % (rcvd.dport, sent.dport, rcvd.getlayer(TCP).flags, flags2human(rcvd.getlayer(TCP).flags))
            resultscan.append(co)
    print "srcport, dstport, flags, humanflags"
    for x in resultscan:
        print x

