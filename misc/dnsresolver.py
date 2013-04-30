#!/usr/bin/python
#Author: DiabloHorn
#Adjusted/borrowed code from:
#   http://michael.susens-schurter.com/code/easyadns/try4.py
#   http://www.catonmat.net/blog/asynchronous-dns-resolution/

import sys
import time
import adns

dodebug = False
pending = dict()
resolver = adns.init()
ARECORD = adns.rr.A

def usage():
    print 'DiabloHorn http://diablohorn.wordpress.com'
    print 'Mass Resolve name2ip (Arecord)'
    print sys.argv[0] + ' <filename>'
    print 'cat <filename> | ' + sys.argv[0]
    sys.exit()

def submitquery(queryname,querytype):
    sbmqry = resolver.submit(name, querytype)
    pending[sbmqry] = name         
    
if __name__ == "__main__":   
    inputdata = None
    if len(sys.argv) == 1:
        #check if we are running interactively
        if sys.stdin.isatty():
            usage()
        inputdata = sys.stdin
    elif len(sys.argv) == 2:
        #check if someone needs the how-to
        if sys.argv[1].lower() == '-h':
            usage()
        else:
            inputdata = file(sys.argv[1]).readlines()
    else:
        usage()    
        
    for name in inputdata:
        name = name.strip()
        if name:     
            submitquery(name,ARECORD)

    while len(resolver.allqueries()) > 0:
        queriescompleted = resolver.completed()
        if queriescompleted:
            if dodebug: print >> sys.stderr, "Completed: %d" % len(queriescompleted)
            for query in queriescompleted:
                qryres = query.check()
                #example answer data
                #(0, 'www.l.google.com', 1167604334, ('216.239.37.99', '216.239.37.104'))
                if qryres[3]:
                    print pending[query], ' '.join(qryres[3])
                else:
                    print pending[query],"RESVERROR"
        else:
            if dodebug: print >> sys.stderr, "Sleeping...3s"
            time.sleep(3)
