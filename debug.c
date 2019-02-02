#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>

/**************************************************************
 *
 * Function:            printContents()
 *
 * Description:         Debug function to dump the message 
 *                      contents to the log.
 *
 *                      Print the contents in both HEX and ASCII
 *
 **************************************************************/
void printContents(char *buffer, int length) {

    int i,j;

    if(length != 0) {
        fprintf(stdout, "\nDATA\n");
    }

    for(i = 0; i < length; i++)
    {
        if( i != 0 && i%16 == 0)
        {
            // Line is complete. Print the ASCII for the line
            fprintf(stdout, "         ");
            for(j = i-16; j<i; j++)
            {
                // Check for byte being a printable ASCII character
                if(buffer[j]>=32 && buffer[j]<=128) {
                    fprintf(stdout, "%c", (unsigned char) buffer[j]);
                } else {
                    // Unprintable character. Print a dot.
                    fprintf(stdout, ".");
                }
            }
            fprintf(stdout, "\n");
        }

        // Start of the line
        if(i%16 == 0){
            fprintf(stdout, "   ");
        }

        // Print the hex code for the byte
        fprintf(stdout, " %02X",(unsigned char)buffer[i]);

        // Check for the last character
        if( i == length-1)
        {
            // Print the extra spaces required to pad for the ASCII print
            for(j = 0;j < 15-i%16; j++)
            {
                fprintf(stdout, "   ");
            }

            // Print the standard padding spaces
            fprintf(stdout, "         ");

            for(j = i-i%16 ; j<=i ; j++)
            {
                // Check for byte being a printable ASCII character
                if(buffer[j]>=32 && buffer[j]<=128) {
                    fprintf(stdout, "%c",(unsigned char)buffer[j]);
                } else {
                    // Unprintable character. Print a dot.
                    fprintf(stdout, ".");
                }
            }

            fprintf(stdout,  "\n" );
        }
    }
}

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

    fprintf(stdout, "IP Header\n");
    fprintf(stdout, "   |-IP Version\t\t: %d\n", ipHeader->version);
    fprintf(stdout, "   |-IP Header Length\t: %d Bytes\n", (ipHeader->ihl) * 4);
    fprintf(stdout, "   |-Type Of Service\t: %d\n", (unsigned int) ipHeader->tos);
    fprintf(stdout, "   |-IP Total Length\t: %d Bytes(Packet size)\n", ntohs(ipHeader->tot_len));
//    fprintf(stdout, "   |-Identification\t: %d\n", ntohs(ipHeader->id));
    fprintf(stdout, "   |-TTL\t\t: %d\n", (unsigned int) ipHeader->ttl);
    fprintf(stdout, "   |-Protocol\t\t: %d\n", (unsigned int) ipHeader->protocol);
//    fprintf(stdout, "   |-Checksum\t\t: %d\n", ntohs(ipHeader->check));
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

    fprintf(stdout, "***********************UDP Packet*************************\n");

    printIPHeader(buffer, length);

    fprintf(stdout, "\nUDP Header\n");
    fprintf(stdout, "   |-Source Port\t: %d\n", ntohs(udpHeader->source));
    fprintf(stdout, "   |-Destination Port\t: %d\n", ntohs(udpHeader->dest));
    fprintf(stdout, "   |-UDP Length\t\t: %d\n", ntohs(udpHeader->len));
    fprintf(stdout, "   |-UDP Checksum\t: %d\n", ntohs(udpHeader->check));
    fprintf(stdout, "   |-UDP Data Length\t: %d\n", (int)(ntohs(udpHeader->len) - sizeof(struct udphdr)));
    // Dump the UDP data. Offset by the IP and TCP headers
    printContents(buffer + ipHeaderLength + sizeof(struct udphdr), length - ipHeaderLength - sizeof(struct udphdr));
    fprintf(stdout, "***********************************************************\n\n");

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
    unsigned int tcpDataLength = length - ipHeaderLength - tcpHeader->doff * 4;

    fprintf(stdout, "***********************TCP Packet*************************\n");

    printIPHeader(buffer, length);

    fprintf(stdout, "\nTCP Header\n");

    fprintf(stdout, "   |-Source Port\t: %u\n", ntohs(tcpHeader->source));
    fprintf(stdout, "   |-Destination Port\t: %u\n", ntohs(tcpHeader->dest));
    fprintf(stdout, "   |-Sequence Number\t: %u\n", ntohl(tcpHeader->seq));
    fprintf(stdout, "   |-Acknowledge Number\t: %u\n", ntohl(tcpHeader->ack_seq));
    fprintf(stdout, "   |-Header Length\t: %d Bytes\n", (unsigned int) tcpHeader->doff * 4);
//    fprintf(stdout, "   |-Urgent Flag\t: %d\n", (unsigned int) tcpHeader->urg);
    fprintf(stdout, "   |-Ack Flag\t\t: %d\n", (unsigned int) tcpHeader->ack);
//    fprintf(stdout, "   |-Push Flag\t\t: %d\n", (unsigned int) tcpHeader->psh);
//    fprintf(stdout, "   |-Reset Flag\t\t: %d\n", (unsigned int) tcpHeader->rst);
    fprintf(stdout, "   |-Synchronise Flag\t: %d\n", (unsigned int) tcpHeader->syn);
    fprintf(stdout, "   |-Finish Flag\t: %d\n", (unsigned int) tcpHeader->fin);
//    fprintf(stdout, "   |-Window\t\t: %d\n", ntohs(tcpHeader->window));
//    fprintf(stdout, "   |-Checksum\t\t: %d\n", ntohs(tcpHeader->check));
//    fprintf(stdout, "   |-Urgent Pointer\t: %d\n", tcpHeader->urg_ptr);
    fprintf(stdout, "   |-TCP Data Length\t: %d\n", tcpDataLength);
    // Dump the TCP data. Offset by the IP and TCP headers
    printContents(buffer + ipHeaderLength + tcpHeader->doff * 4, tcpDataLength);
    fprintf(stdout, "***********************************************************\n\n");

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

    fprintf(stdout, "***********************ICMP Packet*************************\n");

    printIPHeader(buffer, length);

    fprintf(stdout, "ICMP Header\n");
    fprintf(stdout, "   |-Type\t\t: %d",(unsigned int)(icmpHeader->type));

    if((unsigned int)(icmpHeader->type) == ICMP_ECHO) {
        fprintf(stdout, "  (ICMP Echo)\n");
    } else if((unsigned int)(icmpHeader->type) == ICMP_ECHOREPLY) {
        fprintf(stdout, "  (ICMP Echo Reply)\n");
    } else if((unsigned int)(icmpHeader->type) == ICMP_DEST_UNREACH) {
        fprintf(stdout, "  (Dest Unreachable)\n");
    }

    fprintf(stdout, "   |-Code\t\t: %d\n",(unsigned int)(icmpHeader->code));
    fprintf(stdout, "   |-Checksum\t\t: %d\n",ntohs(icmpHeader->checksum));
    fprintf(stdout, "***********************************************************\n\n");

}