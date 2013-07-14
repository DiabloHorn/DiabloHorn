#!/bin/bash
#DiabloHorn http://diablohorn.wordpress.com
unset LD_PRELOAD
gcc -Wall src/generateRSAkeypair.c -o generateRSAkeypair -lssl -lcrypto
