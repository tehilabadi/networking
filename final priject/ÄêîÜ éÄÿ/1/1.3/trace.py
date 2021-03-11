from scapy.all import*
host = "8.8.4.4"
flag = True
ttl=1
while flag:
	ans= sr1(IP(dst=host,ttl=ttl)/ICMP(),timeout=1)
	if ans is None:
		ttl+=1
		continue
	if ans.type == 0: # checking for  ICMP echo-reply
		flag = False
	else:
		ttl +=1
print("ttl is: ",ttl)
