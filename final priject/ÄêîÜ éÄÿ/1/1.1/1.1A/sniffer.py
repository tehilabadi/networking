#!/usr/bin/env python3
from scapy.all import*
def pket(pkt):
	pkt.show()
	
pkt = sniff(iface=['enp0s3'], filter='icmp', prn=pket)
