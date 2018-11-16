#include <sys/socket.h>
#include <netinet/in.h>	
#include <netinet/ip.h> /* declarations for tcp header */
#include <netinet/tcp.h> /* declarations for ip header */    
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

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


int main(int argc, char* argv[])
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

    /* vars that could be from command line */
    char* destAddr;
    uint16_t destPort;
    char* sourceAddr;
    uint16_t sourcePort;
    uint32_t seqNumber;
    uint32_t ackNumber;

    /* Getting command line args */
    sourceAddr = SOURCE_ADDR;
    sourcePort = SOURCE_PORT;
    destAddr = DEST_ADDR;
    destPort = DEST_PORT;
    seqNumber = random();
    ackNumber = TCP_DEFAULT_ACK;

    if(argc >= 5)
    {
        sourceAddr = argv[1];
        sourcePort = atoi(argv[2]);
        destAddr = argv[3];
        destPort = atoi(argv[4]);

        if(argc >= 6)
        {
            seqNumber = atoi(argv[5]);

            if(argc == 7)
            {
                ackNumber = atoi(argv[6]);
            }
        }
    }


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
    tcpHeader->th_flags = TH_SYN;	/* initial connection request */
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

    //while(1)
    //{
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

        //sleep(1);
    //}

    return 0;
}