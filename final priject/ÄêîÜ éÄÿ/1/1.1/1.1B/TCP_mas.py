from scapy.all import*
a = IP()
a.src='10.0.2.4'
a.dst ='8.8.4.4' 
b = TCP()
b.dport=23
p = a/b 
send(p)
