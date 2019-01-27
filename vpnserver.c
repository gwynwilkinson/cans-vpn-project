#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <netdb.h>


#define PORT_NUMBER 55555
#define BUFF_SIZE 2000

struct sockaddr_in peerAddr;

int createTunDevice() {
   int tunfd;
   struct ifreq ifr;
   memset(&ifr, 0, sizeof(ifr));

   ifr.ifr_flags = IFF_TUN | IFF_NO_PI;  

   tunfd = open("/dev/net/tun", O_RDWR);
   ioctl(tunfd, TUNSETIFF, &ifr);       

   if( tunfd == -1 ) {
     printf("Error opening TUN device!\n");
     return 0;
   } else {
     printf("TUN FD = %d\n", tunfd);
   }

   ioctl(tunfd, TUNSETIFF, &ifr);

   printf("Configuring the TUN0 device as 10.4.0.250/24\n");
   int retVal = system("/sbin/ifconfig tun0 10.4.0.250/24 up");
   if(retVal != 0) {
     printf("Returned Error code %d\n", retVal);
     exit(EXIT_FAILURE);
   }

   
   return tunfd;
}

int initUDPServer() {
    int sockfd;
    struct sockaddr_in server;
    char buff[100];

    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;                 
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(PORT_NUMBER);        

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    bind(sockfd, (struct sockaddr*) &server, sizeof(server)); 

    // Wait for the VPN client to "connect".
    bzero(buff, 100);
    int peerAddrLen = sizeof(struct sockaddr_in);
    int len = recvfrom(sockfd, buff, 100, 0,                  
                (struct sockaddr *) &peerAddr, &peerAddrLen);

    
    printf("Connected to address %s from port %d. Msg:- %s\n", inet_ntoa(peerAddr.sin_addr), peerAddr.sin_port, buff);

    return sockfd;
}

void tunSelected(int tunfd, int sockfd){
  int  len, size;
  char buff[BUFF_SIZE];
  bzero(buff, BUFF_SIZE);
  len = read(tunfd, buff, BUFF_SIZE);

  printf("Got a packet from TUN. Length:- %d\n", len);

  size = sendto(sockfd, buff, len, 0, (struct sockaddr *) &peerAddr,
		sizeof(peerAddr));

  printf("Sent %d to the socket.\n", size);
}

void socketSelected (int tunfd, int sockfd){
  int  len;
  char buff[BUFF_SIZE];

  bzero(buff, BUFF_SIZE);
  len = recvfrom(sockfd, buff, BUFF_SIZE, 0, NULL, NULL);
  printf("Got a packet from the tunnel socket. Sending to TUN. Length %d\n", len);

  write(tunfd, buff, len);

}

int main (int argc, char * argv[]) {
  int tunfd, sockfd, retVal;

   // Set the ip forwarding - sysctl net.ipv4.ip_forward=1
   printf("Auto configuring IP forwarding\n ");
   retVal = system("sysctl net.ipv4.ip_forward=1");

   if(retVal != 0) {
     printf("Configuring IP forwarding returned Error code %d\n", retVal);
     exit(EXIT_FAILURE);
   }

   tunfd  = createTunDevice();
   sockfd = initUDPServer();

   // Enter the main loop
   while (1) {
     fd_set readFDSet;

     FD_ZERO(&readFDSet);
     FD_SET(sockfd, &readFDSet);
     FD_SET(tunfd, &readFDSet);
     select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

     if (FD_ISSET(tunfd,  &readFDSet)) tunSelected(tunfd, sockfd);
     if (FD_ISSET(sockfd, &readFDSet)) socketSelected(tunfd, sockfd);
  }
}
 
