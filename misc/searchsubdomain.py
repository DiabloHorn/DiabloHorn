#!/usr/bin/env python
#Author: DiabloHorn http://diablohorn.wordpress.com

import sys
import re

try:
    from bs4 import BeautifulSoup
    import requests
except ImportError, e:
    print e
    print 'You will need all of the following modules:'
    print 'python-bs4'
    print 'pyhton-requests'
    sys.exit()

#global vars
subdomains = list()

"""
    start of search engines 
"""
#search engine url defines
googlesearchengine = 'http://www.google.com/search'
bingsearchengine = 'http://www.bing.com/search'
baidusearchengine = 'http://www.baidu.com/s'
ixquicksearchengine = 'https://ixquick.com/do/search'
yandexsearchengine = 'http://www.yandex.com/yandsearch'

def getgoogleresults(maindomain,searchparams):
    regexword = r'(http://|https://){0,1}(.*)' + maindomain.replace('.','\.')
    try:
        content = requests.get(googlesearchengine,params=searchparams).content
    except:
        print >> sys.stderr, 'Skipping this search engine'
        return        
    soup = BeautifulSoup(content)
    links = soup.find_all('cite')
    extract = re.compile(regexword)
    for i in links:
        match = extract.match(i.text)
        if match:
            res = match.group(2).strip() + maindomain
            if res not in subdomains:
                subdomains.append(res)

def getbingresults(maindomain,searchparams):
    regexword = r'(http://|https://){0,1}(.*)' + maindomain.replace('.','\.')
    try:
        content = requests.get(bingsearchengine,params=searchparams).content
    except:
        print >> sys.stderr, 'Skipping this search engine'
        return    
    soup = BeautifulSoup(content)
    links = soup.find_all('cite')
    extract = re.compile(regexword)
    for i in links:
        match = extract.match(i.text)
        if match:
            res = match.group(2).strip() + maindomain
            if res not in subdomains:
                subdomains.append(res)

def getbaiduresults(maindomain,searchparams):
    regexword = r'(http://|https://){0,1}(.*)' + maindomain.replace('.','\.')
    try:
        content = requests.get(baidusearchengine,params=searchparams).content
    except:
        print >> sys.stderr, 'Skipping this search engine'
        return
    soup = BeautifulSoup(content)
    links = soup.find_all('span','g') #<span class="g">
    extract = re.compile(regexword)
    for i in links:
        match = extract.match(i.text)
        if match:
            res = match.group(2).strip() + maindomain
            if res not in subdomains:
                subdomains.append(res)

def getixquickresults(maindomain,searchparams):
    regexword = r'(http://|https://){0,1}(.*)' + maindomain.replace('.','\.')
    try:
        content = requests.post(ixquicksearchengine,data=searchparams).content
    except:
        print >> sys.stderr, 'Skipping this search engine'
        return        
    soup = BeautifulSoup(content)
    links = soup.find_all('span','url') #<span class="url">
    extract = re.compile(regexword)
    for i in links:
        match = extract.match(i.text)
        if match:
            res = match.group(2).strip() + maindomain
            if res not in subdomains:
                subdomains.append(res)

def getyandexresults(maindomain,searchparams):
    regexword = r'(http://|https://){0,1}(.*)' + maindomain.replace('.','\.')
    try:
        content = requests.get(yandexsearchengine,params=searchparams).content
    except:
        print >> sys.stderr, 'Skipping this search engine'
        return        
    soup = BeautifulSoup(content)
    links = soup.find_all('a','b-serp2-item__title-link')
    extract = re.compile(regexword)
    for i in links:
        match = extract.match(i['href'])
        if match:
            res = match.group(2).strip() + maindomain
            if res not in subdomains:
                subdomains.append(res)
"""
    end of the search engines
"""

def usage():
    print 'DiabloHorn http://diablohorn.wordpress.com'
    print 'Search subdomains'
    print sys.argv[0] + ' <domain.tld>'
    print 'Ex: ' + sys.argv[0] + ' wordpress.com'
    sys.exit()

if __name__ == "__main__":
    if len(sys.argv) !=2:
        usage()

    maindomain = '.' + sys.argv[1]    
    searchword = 'site:' + maindomain[1:]

    searchparam = {'text':searchword}
    getyandexresults(maindomain,searchparam)

    if len(subdomains) > 3:
        for i in range(0,3):
            searchword += ' -site:' + subdomains[i]

    searchparam = {'q':searchword,'oq':searchword}
    getgoogleresults(maindomain,searchparam)

    searchword = 'site: ' + maindomain[1:] #reset searchword
    if len(subdomains) > 6:
        for i in range(0,6):
            searchword += ' -site:' + subdomains[i]

    searchparam = {'wd':searchword}
    getbaiduresults(maindomain,searchparam)

    searchword = 'site: ' + maindomain[1:] #reset searchword
    for i in subdomains:
        searchword += ' -site:' + i
    searchparam = {'q':searchword}
    getbingresults(maindomain,searchparam)

    searchword = 'site: ' + maindomain[1:] #reset searchword
    for i in subdomains:
        searchword += ' -site:' + i    
    searchparam = {'cmd':'process_search','query':searchword}    
    getixquickresults(maindomain,searchparam)

    subdomains.sort()
    for i in subdomains:
        print i 
