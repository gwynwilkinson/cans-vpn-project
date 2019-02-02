#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include<netinet/ip_icmp.h>

/**************************************************************
 *
 * Function:            printIPHeader()
 *
 * Description:         Debug function to dump the contents of
 *                      the packet IP header.
 *
 **************************************************************/
void printIPHeader(char *buffer, int length) {

    struct sockaddr_in source;
    struct sockaddr_in dest;
    struct iphdr *ipHeader = (struct iphdr *) buffer;

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = ipHeader->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = ipHeader->daddr;

    fprintf(stdout, "\n");
    fprintf(stdout, "IP Header\n");
    fprintf(stdout, "   |-IP Version\t\t: %d\n", (unsigned int) ipHeader->version);
    fprintf(stdout, "   |-IP Header Length\t: %d DWORDS or %d Bytes\n", ipHeader->ihl,
            (ipHeader->ihl) * 4);
    fprintf(stdout, "   |-Type Of Service\t: %d\n", (unsigned int) ipHeader->tos);
    fprintf(stdout, "   |-IP Total Length\t: %d Bytes(Packet size)\n", ntohs(ipHeader->tot_len));
    fprintf(stdout, "   |-Identification\t: %d\n", ntohs(ipHeader->id));
    fprintf(stdout, "   |-TTL\t\t: %d\n", (unsigned int) ipHeader->ttl);
    fprintf(stdout, "   |-Protocol\t\t: %d\n", (unsigned int) ipHeader->protocol);
    fprintf(stdout, "   |-Checksum\t\t: %d\n", ntohs(ipHeader->check));
    fprintf(stdout, "   |-Source IP\t\t: %s\n", inet_ntoa(source.sin_addr));
    fprintf(stdout, "   |-Destination IP\t: %s\n", inet_ntoa(dest.sin_addr));

}

/**************************************************************
 *
 * Function:            printUDPHeader()
 *
 * Description:         Debug function to dump the contents of
 *                      the packet UDP header.
 *
 **************************************************************/
void printUDPHeader(char *buffer, int length) {

    struct iphdr *ipHeader = (struct iphdr *) buffer;
    unsigned int ipHeaderLength = ipHeader->ihl * 4;
    struct udphdr *udpHeader = (struct udphdr *) (buffer + ipHeaderLength);

    fprintf(stdout, "\n\n***********************UDP Packet*************************\n");

    printIPHeader(buffer, length);

    fprintf(stdout, "\nUDP Header\n");
    fprintf(stdout, "   |-Source Port      : %d\n", ntohs(udpHeader->source));
    fprintf(stdout, "   |-Destination Port : %d\n", ntohs(udpHeader->dest));
    fprintf(stdout, "   |-UDP Length       : %d\n", ntohs(udpHeader->len));
    fprintf(stdout, "   |-UDP Checksum     : %d\n", ntohs(udpHeader->check));
    fprintf(stdout, "\n");
    // TODO - print raw UDP data

    fprintf(stdout, "\n###########################################################");

}

/**************************************************************
 *
 * Function:            printTCPHeader()
 *
 * Description:         Debug function to dump the contents of
 *                      the packet TCP header.
 *
 **************************************************************/
void printTCPHeader(char *buffer, int length) {

    struct iphdr *ipHeader = (struct iphdr *) buffer;
    unsigned int ipHeaderLength = ipHeader->ihl * 4;
    struct tcphdr *tcpHeader = (struct tcphdr *) (buffer + ipHeaderLength);

    fprintf(stdout, "\n\n***********************TCP Packet*************************\n");

    printIPHeader(buffer, length);

    fprintf(stdout, "\nTCP Header\n");

    fprintf(stdout, "   |-Source Port      : %u\n", ntohs(tcpHeader->source));
    fprintf(stdout, "   |-Destination Port : %u\n", ntohs(tcpHeader->dest));
    fprintf(stdout, "   |-Sequence Number    : %u\n", ntohl(tcpHeader->seq));
    fprintf(stdout, "   |-Acknowledge Number : %u\n", ntohl(tcpHeader->ack_seq));
    fprintf(stdout, "   |-Header Length      : %d DWORDS or %d BYTES\n", (unsigned int) tcpHeader->doff,
            (unsigned int) tcpHeader->doff * 4);
    fprintf(stdout, "   |-Urgent Flag          : %d\n", (unsigned int) tcpHeader->urg);
    fprintf(stdout, "   |-Acknowledgement Flag : %d\n", (unsigned int) tcpHeader->ack);
    fprintf(stdout, "   |-Push Flag            : %d\n", (unsigned int) tcpHeader->psh);
    fprintf(stdout, "   |-Reset Flag           : %d\n", (unsigned int) tcpHeader->rst);
    fprintf(stdout, "   |-Synchronise Flag     : %d\n", (unsigned int) tcpHeader->syn);
    fprintf(stdout, "   |-Finish Flag          : %d\n", (unsigned int) tcpHeader->fin);
    fprintf(stdout, "   |-Window         : %d\n", ntohs(tcpHeader->window));
    fprintf(stdout, "   |-Checksum       : %d\n", ntohs(tcpHeader->check));
    fprintf(stdout, "   |-Urgent Pointer : %d\n", tcpHeader->urg_ptr);

    fprintf(stdout, "\n###########################################################");

    // TODO - Dump TCP data.
}

/**************************************************************
 *
 * Function:            printICMPHeader()
 *
 * Description:         Debug function to dump the contents of
 *                      the packet ICMP header.
 *
 **************************************************************/
void printICMPHeader(char *buffer, int length) {

    struct iphdr *ipHeader = (struct iphdr *) buffer;
    unsigned int ipHeaderLength = ipHeader->ihl * 4;
    struct icmphdr *icmpHeader = (struct icmphdr *)(buffer + ipHeaderLength);

    fprintf(stdout, "\n\n***********************ICMP Packet*************************\n");
    fprintf(stdout, "ICMP Header\n");
    fprintf(stdout, "   |-Type : %d",(unsigned int)(icmpHeader->type));

    if((unsigned int)(icmpHeader->type) == 11)
    {
        fprintf(stdout, "  (TTL Expired)\n");
    }
    else if((unsigned int)(icmpHeader->type) == ICMP_ECHOREPLY)
    {
        fprintf(stdout, "  (ICMP Echo Reply)\n");
    }

    fprintf(stdout, "   |-Code : %d\n",(unsigned int)(icmpHeader->code));
    fprintf(stdout, "   |-Checksum : %d\n",ntohs(icmpHeader->checksum));
    fprintf(stdout, "\n");
    fprintf(stdout, "\n###########################################################");

}