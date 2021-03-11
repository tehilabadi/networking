#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <sys/time.h>
#define SIZE 1500

/* Ethernet header */
struct ethheader {
  u_char  ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
  u_char  ether_shost[ETHER_ADDR_LEN]; /* source host address */
  u_short ether_type;                  /* IP? ARP? RARP? etc */
};

/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address 
  struct  in_addr    iph_destip;   //Destination IP address 
};

/* ICMP Header  */
struct icmpheader {
  unsigned char icmp_type; // ICMP message type
  unsigned char icmp_code; // Error code
  unsigned short int icmp_chksum; //Checksum for ICMP Header and data
  unsigned short int icmp_id;     //Used for identifying request
  unsigned short int icmp_seq;    //Sequence number
  struct timeval icmp_time_stamp;
};

unsigned short in_cksum (unsigned short *buf, int length)
{
   unsigned short *w = buf;
   int nleft = length;
   int sum = 0;
   unsigned short temp=0;

   /*
    * The algorithm uses a 32 bit accumulator (sum), adds
    * sequential 16 bit words to it, and at the end, folds back all 
    * the carry bits from the top 16 bits into the lower 16 bits.
    */
   while (nleft > 1)  {
       sum += *w++;
       nleft -= 2;
   }

   /* treat the odd byte at the end, if any */
   if (nleft == 1) {
        *(u_char *)(&temp) = *(u_char *)w ;
        sum += temp;
   }

   /* add back carry outs from top 16 bits to low 16 bits */
   sum = (sum >> 16) + (sum & 0xffff);  // add hi 16 to low 16 
   sum += (sum >> 16);                  // add carry 
   return (unsigned short)(~sum);
}

void send_raw_ip_packet(struct ipheader* ip)
{
    struct sockaddr_in dest_info;
    int enable = 1;

    // Step 1: Create a raw network socket.
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    // Step 2: Set socket option.
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));

    // Step 3: Provide needed information about destination.
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->iph_destip;

    // Step 4: Send the packet out.
    int bit=sendto(sock, ip, ntohs(ip->iph_len), 0, (struct sockaddr *)&dest_info, sizeof(dest_info));
    close(sock);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header,const u_char *packet)
{
    
    struct ethheader *eth = (struct ethheader *)packet;
    struct ipheader * ip = (struct ipheader *)(packet + sizeof(struct ethheader));
    unsigned char type=ip->iph_protocol;
     /*chack if icmp prtocol*/
    if(ip->iph_protocol == IPPROTO_ICMP) {
       struct icmpheader *icmp = (struct icmpheader *) (packet + sizeof(struct ethheader) + sizeof(struct ipheader));
       /*chack if its requset*/
       if(icmp-> icmp_type == 8){
       char buff[SIZE];
       memset(buff, 0, SIZE);
       /*calculate the data length*/
       int len=header->caplen - (sizeof(struct ethheader) + sizeof(struct ipheader) + sizeof(struct icmpheader));
       /*fill up the buffer*/
       for(int i=0;i <len;i++){
       buff[sizeof(struct ipheader) + sizeof(struct icmpheader)+i]=packet[len+i];
       }
       struct icmpheader *new_icmp = (struct icmpheader *)(sizeof(struct ipheader)+buff);
       new_icmp->icmp_type =0;
       new_icmp->icmp_id=icmp->icmp_id;
       new_icmp->icmp_seq=icmp->icmp_seq;
       new_icmp->icmp_time_stamp=icmp->icmp_time_stamp;
       new_icmp->icmp_chksum = 65535;
       new_icmp->icmp_chksum = in_cksum((unsigned short *)new_icmp,sizeof(struct icmpheader)+len); 
       struct ipheader *new_ip = (struct ipheader *) buff;
       new_ip->iph_ver = ip->iph_ver;
       new_ip->iph_ihl = ip->iph_ihl;
       new_ip->iph_ttl = ip->iph_ttl;
       new_ip->iph_sourceip.s_addr =ip->iph_destip.s_addr;
       new_ip->iph_destip.s_addr =ip->iph_sourceip.s_addr;
       new_ip->iph_protocol = ip->iph_protocol;
       new_ip->iph_len = ip->iph_len;
       send_raw_ip_packet (new_ip);
       }
    }

}

int main()
{

pcap_t *handle;
char errbuf[PCAP_ERRBUF_SIZE];
struct bpf_program fp;
char filter_exp[] = "icmp";
bpf_u_int32 net;
// Step 1: Open live pcap session on NIC 
handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
if(handle==NULL){
printf("Failed pcap_open_live function!\n");
exit(1);
}
// Step 2: Compile filter_exp into BPF psuedo-code
pcap_compile(handle, &fp, filter_exp, 0, net);
// Step 3: Setting a filter
pcap_setfilter(handle, &fp);
// Step 4: Capture packets
pcap_loop(handle, -1, got_packet, NULL);
pcap_close(handle); //Close the handle
return 0;
}
