#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <stdlib.h>

#define BUFF_SIZE 2000
#define PORT_NUMBER 55555
#define SERVER_IP "192.168.1.129" 
struct sockaddr_in peerAddr;

int createTunDevice() {
   int tunfd;
   struct ifreq ifr;
   memset(&ifr, 0, sizeof(ifr));

   ifr.ifr_flags = IFF_TUN | IFF_NO_PI;  

   tunfd = open("/dev/net/tun", O_RDWR);
   if( tunfd == -1 ) {
     printf("Error opening TUN device!\n");
     return 0;
   } else {
     printf("TUN FD = %d\n", tunfd);
   }

   ioctl(tunfd, TUNSETIFF, &ifr);

   printf("Configuring the TUN0 device as 10.4.2.99/24\n");
   int retVal = system("ifconfig tun0 10.4.2.99/24 up");
   if(retVal != 0) {
     printf("Returned Error code %d\n");
   }
   

   return tunfd;
}

int connectToUDPServer(){
    int sockfd;
    char *hello="Hello";

    memset(&peerAddr, 0, sizeof(peerAddr));
    peerAddr.sin_family = AF_INET;
    peerAddr.sin_port = htons(PORT_NUMBER);
    peerAddr.sin_addr.s_addr = inet_addr(SERVER_IP);

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    printf("Opened socket. FD = %d\n", sockfd);
    
    // Send a hello message to "connect" with the VPN server
    sendto(sockfd, hello, strlen(hello), 0,
                (struct sockaddr *) &peerAddr, sizeof(peerAddr));

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
    printf("Got a packet from the tunnel socket. Length %d\n", len);

    write(tunfd, buff, len);

}
int main (int argc, char * argv[]) {
   int tunfd, sockfd;

   tunfd  = createTunDevice();
   sockfd = connectToUDPServer();

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
 
