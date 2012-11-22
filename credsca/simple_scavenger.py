#!/usr/bin/env python
#CredentialScavenger - credsca
#DiabloHorn http://diablohorn.wordpress.com
#non threaded on purpose
import sys
import os
from credcheck import credverify
from credcheck import database

if __name__ == "__main__":
    lmods = credverify.loadmodules('modules/','cc.conf')
    db = database.Database()
    DBNAME = 'creds.db'
    if not os.path.exists(DBNAME):
        db.openconn(DBNAME)
        db.createcredstable()
    db.openconn(DBNAME)    
    #non optimized on purpose
    with open(sys.argv[1]) as f:
        for i in f:
            creds = credverify.checkcreds(i,lmods)
            if creds is not None:
                print creds
                for k,v in creds.iteritems():
                    db.insertcreds(v[0],v[1],v[2],k)
    db.close()
