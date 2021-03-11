#!/usr/bin/env python3
from scapy.all import*
def pket(pkt):
	if pkt[1].type== 8:
		pkt.show()
		dest=pkt[1].dst
		src=pkt[1].src
		a = IP()
		a.src=dest
		a.dst =src
		b = ICMP()
		b.type=0
		b.id=pkt[2].id
		b.seq=pkt[2].seq
		load=pkt[3].load
		p = (a/b)/load 
		send(p)	
pkt = sniff(iface=['br-f5e47f85ffdd','enp0s3'], filter='icmp', prn=pket)
