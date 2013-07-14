#!/bin/bash
#DiabloHorn http://diablohorn.wordpress.com
unset LD_PRELOAD
#check if we have received arguments
if [ -z "$@" ]
then
    echo "Please provide the complete sslsniff commandline as argument, ex:"
    echo "$0 sslsniff -a -c /tmp/cacert.pem -s 8443 -w /tmp/slog.txt"
    exit 0
fi

#check if the needed hooking library is present
if [ ! -f libmyRSAgeneratekey.so ]
then
    echo "libmyRSAgeneratekey.so not present, please compile first"
    exit 0
fi

export LD_PRELOAD=$PWD/libmyRSAgeneratekey.so
echo "Using hook library: "$LD_PRELOAD

# runs whatever command is given to it
# ex: 
# ./sslsniff_hooked.sh sslsniff -a -c /tmp/cacert.pem -s 8443 -w /tmp/slog.txt
$@
