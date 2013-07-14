#!/bin/bash
#DiabloHorn http://diablohorn.wordpress.com
unset LD_PRELOAD
gcc -Wall -fPIC -c -o myRSAgeneratekey.o src/myRSAgeneratekey.c
gcc -shared -fPIC -Wl,-soname -Wl,libmyRSAgeneratekey.so -o libmyRSAgeneratekey.so myRSAgeneratekey.o
rm myRSAgeneratekey.o
