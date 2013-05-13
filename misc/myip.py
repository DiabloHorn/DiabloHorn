#!/usr/bin/env python
#DiabloHorn http://diablohorn.wordpress.com
#get external ip using multiple sites
#yes I know it's horrible to parse html with regex

import sys
import urllib2
import re

ipproviders = ('http://ip.nu/','http://my.ip.fi/','http://ip.bsd-unix.net/','http://ip.sidn.nl/')
ipextract = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')

def lookupip(addy):
	response = None
	try:
		response = urllib2.urlopen(addy).read()
	except:
		print 'Skipping ' + addy + ' due to urllib2 error'

	if response != None:
		rematch = ipextract.search(response)
		if rematch != None:
			print rematch.group(0)

for provider in ipproviders:
	lookupip(provider)
	

