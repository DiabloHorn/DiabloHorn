#!/usr/bin/env python
#Author: DiabloHorn http://diablohorn.wordpress.com
#POC file2image, to bypass webfilters and other content type scanning engines
# Thanks to Animal for answering questions at 4AM and polishing up midnight thoughts internals


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
    pass
    
def decimg(filename):
    """
    """
    if _sec:
        #do crypto before  
        secunsec(filename,enc=False)
    pass

if __name__ == "__main__":
    if len(sys.argv) < 2:
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
        
    sys.exit()
    filename = sys.argv[1]
    oimgname = "img.png"
    filesize = os.path.getsize(filename)
    #let's start file->image
    #get the file bytes
    (bytesread,rawbytes) = getfilebytes(filename)
    #encode them using base64
    encodedbytes = base64.b64encode(rawbytes)
    del rawbytes
    #get the size of the image necessary to hold our file
    (w,h,d) = getpixsize(len(encodedbytes))
    print "width: " + str(w)
    print "height: " + str(h)
    print "diff: " + str(d)
    #pad to needed length if necessary
    if d > 0:
        for i in range(d):
            encodedbytes += ('\0')
    print "Filesize: " + str(filesize)
    print "Padding: " + str(d)
    print "Finalsize: " + str(len(encodedbytes))
    #create the image using our base64 encoded bytes
    imc = Image.frombuffer("RGB", (w,h), encodedbytes,"raw","RGB",0,1)
    #save the image
    imc.save(oimgname)
    #Here we reverse the process we go from image->file
    imo = Image.open(oimgname)
    fr = open("output","wb")
    #get our file data
    rawdata = list(imo.getdata())
    tsdata = ""
    #let's get it back in base64 format and decode it
    for x in rawdata:
        for z in x:
            tsdata += chr(z)
    decdata = base64.b64decode(tsdata)
    del rawdata
    #decoding done, let's write the file
    for a in decdata:
        fr.write('%c' % a)
    fr.close()  
