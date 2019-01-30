#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

/**************************************************************
 *
 * Function:            printIPHeader()
 *
 * Description:         Debug function to dump the contents of
 *                      the packet IP header.
 *
 **************************************************************/
void printIPHeader(char * buffer, int length) {

  struct sockaddr_in source;
  struct sockaddr_in dest;
  struct iphdr *iph = (struct iphdr *)buffer;
  unsigned short iphdrlen;

  iphdrlen =iph->ihl*4;

  memset(&source, 0, sizeof(source));
  source.sin_addr.s_addr = iph->saddr;

  memset(&dest, 0, sizeof(dest));
  dest.sin_addr.s_addr = iph->daddr;

  fprintf(stdout , "\n");
  fprintf(stdout , "IP Header\n");
  fprintf(stdout , "   |-IP Version\t\t: %d\n",(unsigned int)iph->version);
  fprintf(stdout , "   |-IP Header Length\t: %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
  fprintf(stdout , "   |-Type Of Service\t: %d\n",(unsigned int)iph->tos);
  fprintf(stdout , "   |-IP Total Length\t: %d Bytes(Packet size)\n",ntohs(iph->tot_len));
  fprintf(stdout , "   |-Identification\t: %d\n",ntohs(iph->id));
  fprintf(stdout , "   |-TTL\t\t: %d\n",(unsigned int)iph->ttl);
  fprintf(stdout , "   |-Protocol\t\t: %d\n",(unsigned int)iph->protocol);
  fprintf(stdout , "   |-Checksum\t\t: %d\n",ntohs(iph->check));
  fprintf(stdout , "   |-Source IP\t\t: %s\n" , inet_ntoa(source.sin_addr) );
  fprintf(stdout , "   |-Destination IP\t: %s\n" , inet_ntoa(dest.sin_addr) );
  
}

/**************************************************************
 *
 * Function:            printUDPHeader()
 *
 * Description:         Debug function to dump the contents of
 *                      the packet UDP header.
 *
 **************************************************************/
void printUDPHeader(char * buffer, int length) {

  struct iphdr *iph = (struct iphdr *)buffer;
  unsigned short iphdrlen;
  
  iphdrlen = iph->ihl*4;

  struct udphdr *udph = (struct udphdr*)(buffer + iphdrlen);

  int header_size =  iphdrlen + sizeof udph;

  fprintf(stdout, "\n\n***********************UDP Packet*************************\n");

  printIPHeader(buffer,length);

  fprintf(stdout, "\nUDP Header\n");
  fprintf(stdout, "   |-Source Port      : %d\n" , ntohs(udph->source));
  fprintf(stdout, "   |-Destination Port : %d\n" , ntohs(udph->dest));
  fprintf(stdout, "   |-UDP Length       : %d\n" , ntohs(udph->len));
  fprintf(stdout, "   |-UDP Checksum     : %d\n" , ntohs(udph->check));
  fprintf(stdout, "\n");
  fprintf(stdout, "IP Header\n");
//  PrintData(buffer , iphdrlen);

  fprintf(stdout, "UDP Header\n");
//  PrintData(buffer+iphdrlen , sizeof udph);

  fprintf(stdout, "Data Payload\n");

  //Move the pointer ahead and reduce the size of string
//  PrintData(Buffer + header_size , Size - header_size);

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
void printTCPHeader(char * buffer, int length) {

  fprintf(stdout, "\n\n***********************TCP Packet*************************\n");

  printIPHeader(buffer, length);

  fprintf(stdout , "\n###########################################################");
  
}
