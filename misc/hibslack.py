#!/usr/bin/env python
#DiabloHorn http://diablohorn.wordpress.com

"""
http://www.blackhat.com/presentations/bh-usa-08/Suiche/BH_US_08_Suiche_Windows_hibernation.pdf
http://stoned-vienna.com/downloads/Hibernation%20File%20Attack/Hibernation%20File%20Format.pdf
https://code.google.com/p/volatility/wiki/HiberAddressSpace
http://superuser.com/questions/83437/hibernate-computer-from-command-line-on-windows-7
http://digital-forensics.sans.org/blog/2014/07/01/hibernation-slack-unallocated-data-from-the-deep-past
http://sandman.msuiche.net/docs/SandMan_Project.pdf
http://kb.vmware.com/selfservice/microsites/search.do?language=en_US&cmd=displayKC&externalId=1004129
http://stackoverflow.com/questions/3217334/python-searching-reading-binary-data
"""
import sys
import os
import mmap
from struct import unpack

XPRESS_SIG = "\x81\x81" + "xpress"

def roundit(num):
    return num + (8-(num % 8))

def dirty_slack_calc(filename):
    file_size = os.path.getsize(filename)
    xpress_size = 0
    
    with open(sys.argv[1], "r+b") as f:
        mm = mmap.mmap(f.fileno(), 0)
        xpress_block = mm.rfind(XPRESS_SIG)
        mm.seek(xpress_block+9)
        xpress_rsize = mm.read(4)
        xpress_size = xpress_block + 13 + roundit((unpack('<I',xpress_rsize)[0] / 4) +1)
    slack_size = file_size - xpress_size
    print "Possible slack (rough estimate): %s b / %s kb / %s mb" % (str(slack_size), str(slack_size / 1024), str(slack_size / 1048576))
      
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print sys.argv[0] + " <hiberfil.sys>"
        sys.exit()
    dirty_slack_calc(sys.argv[1])
