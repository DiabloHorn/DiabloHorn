#!/usr/bin/env python
#Author: DiabloHorn http://diablohorn.wordpress.com
#POC file2image, to bypass webfilters and other content type scanning engines
# Thanks to Animal for answering questions at 4AM and polishing up midnight thoughts internals
#TODO
# - Support large files, split them up into several images
# - Maybe implement encryption...


import sys    
import os
import math
import base64
import getopt
from PIL import Image      

#global vars
_enc = ""
_dec = ""
_sec = False

def usage():
    print "File2Image - Bypassing Content-Filters"
    print "DiabloHorn http://diablohorn.wordpress.com"
    print sys.argv[0] + " <-e|-d> [-s] <filename>.<ext>"
    print "-e = encode file"
    print "-d = decode image"
    print "-s = secure (crypto stuff)"
    print "-h = this help"
    sys.exit()

def getfilebytes(filename,offset=0,maxsize=1048576):
    """
        Get bytes from source file
        place a 1MB restriction
        return the data read and the actual bytes
    """
    fo = open(filename,"rb")    
    fo.seek(offset,0) #seek from current file position
    data = fo.read(maxsize)
    fo.close()
    return (len(data),data)

def getpixsize(size):
    """
        Calculate pixel dimensions based on size
        Also calculate the difference with the original filesize
    """
    width = height = int(math.ceil(math.sqrt(size/3)))
    diff = int(((width * height) * 3) - size)
    return (width,height,diff)

def fp(data):
    """
        fancyprint or something like it
    """
    print "[*] " + str(data)
    
def secunsec(filename,enc=True):
    """
    """
    if(enc):
        fp("Encrypting First")
        pass
    else:
        fp("Decrypting First")
        pass
    pass
    
def encfile(filename):
    """
    """
    if _sec:
        #do crypto before
        secunsec(filename)
        
    (bytesread,rawbytes) = getfilebytes(filename)
    encodedbytes = base64.b64encode(rawbytes)
    del rawbytes    
    (w,h,d) = getpixsize(len(encodedbytes))    
    if d > 0:
        for i in range(d):
            encodedbytes += ('\0')
    imc = Image.frombuffer("RGB", (w,h), encodedbytes,"raw","RGB",0,1)
    imc.save(filename+".png")
            
def decimg(filename):
    """
    """
    if _sec:
        #do crypto before  
        secunsec(filename,enc=False)

    imo = Image.open(filename)
    fr = open(filename+".decoded","wb")
    rawdata = list(imo.getdata())
    tsdata = ""
    for x in rawdata:
        for z in x:
            tsdata += chr(z)
    decdata = base64.b64decode(tsdata)
    del rawdata
    for a in decdata:
        fr.write('%c' % a)
    fr.close()  

if __name__ == "__main__":
    if len(sys.argv) < 3:
        usage()

    try:
        opts, args = getopt.getopt(sys.argv[1:],"e:d:sh",["encode","decode","secure","help"])
    except getopt.GetoptError, err:
        print err
        sys.exit()
        
    for o,a in opts:
        if o in ("-h", "--help"):
            usage()
        elif o in ("-e","--encode"):
            _enc = a
        elif o in ("-d","--decode"):
            _dec = a
        elif o in ("-s","--secure"):
            _sec = True
        else:
            usage()
    
    if len(_enc) != 0:
        fp("Encoding file to image")
        encfile(_enc)
        
    if len(_dec) != 0:
        fp("Decoding image to file")
        decimg(_dec)
