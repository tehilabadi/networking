#!/usr/bin/env python3
from scapy.all import*
def print_pkt(pkt):
	pkt.show()
	
pkt = sniff(iface=['enp0s3'], filter='tcp and host 10.0.2.4 and port 23', prn=print_pkt)
