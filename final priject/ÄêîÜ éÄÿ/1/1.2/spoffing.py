from scapy.all import*
a = IP()
a.src='8.8.4.4'
a.dst = '10.0.2.4'
b = ICMP()
p = a/b 
send(p)
