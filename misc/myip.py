#!/usr/bin/env python
#DiabloHorn http://diablohorn.wordpress.com
#get external ip using http://ip.nu or display full html response if it fails

import urllib2
import re

ipextract = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
response = urllib2.urlopen('http://ip.nu/').read()
if response != None:
	rematch = ipextract.search(response)
	if rematch != None:
		print rematch.group(0)
	else:
		print response
