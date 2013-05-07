#/usr/bin/env awk
#http://stackoverflow.com/questions/6166375/median-of-column-with-awk
#./scanverify.py delayedresponse.pcap 0 | cut -d' ' -f2 | sort -n | awk -f median.awk
{
    count[NR] = $1;
}
END {
    if (NR % 2) {
        print count[(NR + 1) / 2];
    } else {
        print (count[(NR / 2)] + count[(NR / 2) + 1]) / 2.0;
    }
}
