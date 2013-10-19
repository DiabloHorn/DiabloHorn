#!/bin/bash
echo "Don't forget to run this as root!!!"
svn checkout http://impacket.googlecode.com/svn/trunk/ impacket-svn
cd impacket-svn
python setup.py install
