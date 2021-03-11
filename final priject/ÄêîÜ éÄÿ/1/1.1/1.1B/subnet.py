#!/usr/bin/env python3
from scapy.all import*
def print_pkt(pkt):
	pkt.show()

filt = "ip and ("
ip=[]
for i in range(5):
	ip.append("8.8.4.{}".format(str(i)))
for i in ip[:-1]:
    filt = "%shost %s or " % (filt, i)
filt = "%shost %s)" % (filt, ip[-1])
pkt = sniff(iface=['enp0s3'], filter=filt, prn=print_pkt)
