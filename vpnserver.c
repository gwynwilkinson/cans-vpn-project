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
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdbool.h>
#include <getopt.h>
#include "debug.h"

#define BUFF_SIZE 2000

#define ICMP 1
#define TCP 6
#define UDP 17

bool printVerboseDebug = false;
bool printIPHeaders = false;

static struct option long_options[] =
        {
                {"udp-server-port", required_argument, NULL, 'u'},
                {"ip-headers",      no_argument,       NULL, 'i'},
                {"verbose",         no_argument,       NULL, 'v'},
                {"help",            no_argument,       NULL, 'h'},
                {NULL, 0,                              NULL, 0}
        };

struct sockaddr_in peerAddr;
ushort udpPortNumber = 0;

/**************************************************************
 *
 * Function:            createTunDevice()
 *
 * Description:         Creates the TUN
 *                      Configures the TUN IP automatically as 10.4.0.250/24
 *
 **************************************************************/
int createTunDevice() {

    struct ifreq ifr;
    char commandBuffer[70];
    int tunFD;
    int retVal;

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    tunFD = open("/dev/net/tun", O_RDWR);
    if (tunFD == -1) {
        printf("Error opening TUN device!\n");
        return 0;
    }

    ioctl(tunFD, TUNSETIFF, &ifr);

    printf("TUN %s created with FD = %d\n", ifr.ifr_name, tunFD);

    printf("Configuring the %s device as 10.4.0.250/24\n", ifr.ifr_name);

    // Create the interface configuration command for the new interface name
    sprintf(commandBuffer, "/sbin/ifconfig %s 10.4.0.250/24 up", ifr.ifr_name);

    retVal = system(commandBuffer);

    if (retVal != 0) {
        printf("TUN %s interface configuration returned Error code %d\n", ifr.ifr_name, retVal);
        exit(EXIT_FAILURE);
    }

    return tunFD;
}

/**************************************************************
 *
 * Function:            initUDPServer()
 *
 * Description:         Intialises the UDP server listener on
 *                      the Local UDP server port.
 *
 **************************************************************/
int initUDPServer() {
    struct sockaddr_in server;
    struct sockaddr_in localAddr;
    char buff[100];
    int sockFD;
    socklen_t saLen = sizeof(struct sockaddr_in);;
    ssize_t len;

    // Create a local server sockaddr_in structure to bind to
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(udpPortNumber);

    // Create a UDP socket for the listener
    sockFD = socket(AF_INET, SOCK_DGRAM, 0);

    // Bind to the socket
    bind(sockFD, (struct sockaddr *) &server, sizeof(server));

    if (getsockname(sockFD, (struct sockaddr *) &localAddr, &saLen) == -1) {
        perror("getsockname");
        exit(EXIT_FAILURE);
    }

    printf("Created UDP socket. FD = %d. Bound to IP = %s:%d\n",
           sockFD,
           inet_ntoa(localAddr.sin_addr),
           (int) ntohs(localAddr.sin_port));

    // Wait for the VPN client to "connect".
    bzero(buff, 100);

    len = recvfrom(sockFD, buff, 100, 0,
                   (struct sockaddr *) &peerAddr, &saLen);

    printf("New client connection from %s:%d. Initialisation Msg:- %s\n", inet_ntoa(peerAddr.sin_addr),
           peerAddr.sin_port, buff);

    return sockFD;
}

/**************************************************************
 *
 * Function:            tunSelected()
 *
 * Description:         Received a packet on the TUN.
 *                      Send to the UDP socket (tunnel).
 *
 **************************************************************/
void tunSelected(int tunFD, int sockFD) {
    ssize_t len, size;
    char buff[BUFF_SIZE];

    bzero(buff, BUFF_SIZE);
    len = read(tunFD, buff, BUFF_SIZE);

    struct iphdr *ipHeader = (struct iphdr *) buff;

    // Ignore IPv6 packets
    if (ipHeader->version == 6) {
        return;
    }

    if (printVerboseDebug) {
        printf("TUN->Tunnel- Length:- %d\n", (int) len);
    }

    // Debug output, dump the IP and UDP or TCP headers of the buffer contents.
    if (printIPHeaders) {
        if ((unsigned int) ipHeader->protocol == UDP) {
            printUDPHeader(buff, (int) len);
        } else if ((unsigned int) ipHeader->protocol == TCP) {
            printTCPHeader(buff, (int) len);
        } else if ((unsigned int) ipHeader->protocol == ICMP) {
            printICMPHeader(buff, (int) len);
        } else {
            printIPHeader(buff, (int) len);
        }
    }

    size = sendto(sockFD, buff, len, 0, (struct sockaddr *) &peerAddr,
                  sizeof(peerAddr));

    if (size == 0) {
        perror("sendto");
    }
}


/**************************************************************
 *
 * Function:            socketSelected()
 *
 * Description:         Received a packet on the UDPsocket (tunnel)
 *                      Send to the TUN device (application)
 *
 **************************************************************/
void socketSelected(int tunFD, int sockFD) {
    ssize_t len;
    char buff[BUFF_SIZE];
    struct sockaddr_storage remoteAddress;
    socklen_t addrSize = sizeof(remoteAddress);
    struct iphdr *ipHeader = (struct iphdr *) buff;

    bzero(buff, BUFF_SIZE);
    len = recvfrom(sockFD, buff, BUFF_SIZE, 0, (struct sockaddr *) &remoteAddress, &addrSize);

    // Ignore IPv6 packets
    if (ipHeader->version == 6) {
        return;
    }

    if (printVerboseDebug) {
        printf("Tunnel->TUN - Source IP %s:%d - Length %d\n",
               inet_ntoa(((struct sockaddr_in *) &remoteAddress)->sin_addr),
               (int) ntohs(((struct sockaddr_in *) &remoteAddress)->sin_port),
               (int) len);
    }

    // Debug output, dump the IP and UDP or TCP headers of the buffer contents.
    if (printIPHeaders) {
        if ((unsigned int) ipHeader->protocol == UDP) {
            printUDPHeader(buff, (int) len);
        } else if ((unsigned int) ipHeader->protocol == TCP) {
            printTCPHeader(buff, (int) len);
        } else if ((unsigned int) ipHeader->protocol == ICMP) {
            printICMPHeader(buff, (int) len);
        } else {
            printIPHeader(buff, (int) len);
        }
    }

    // Write the packet to the TUN device.
    write(tunFD, buff, (size_t) len);
}


/**************************************************************
 *
 * Function:            printUsage()
 *
 * Description:         Display the help for the command line option.
 *
 *********************************************************************/
void printUsage(int argc, char *argv[]) {
    fprintf(stdout, "\n Usage: %s [options]\n\n", argv[0]);
    fprintf(stdout, " Proof of concept for VPN Server\n\n");
    fprintf(stdout, " Mandatory Options:- \n");
    fprintf(stdout, "   \n");
    fprintf(stdout, "\n Optional Options:- \n");
    fprintf(stdout, "   -u --udp-server-port\t\t: Local UDP Server Port. Default - 55555\n");
    fprintf(stdout, "   -v --verbose\t\t\t: Verbose debug logging. Dumps packet headers to stdout\n");
    fprintf(stdout, "   -i --ip-headers\t\t: Print out IP headers\n");
    fprintf(stdout, "   -h --help\t\t\t: Help\n");
    fprintf(stdout, "\n");
}

/**************************************************************
 *
 * Function:            processCmdLineOptions()
 *
 * Description:         Process the command line options and setup
 *                      the variables based on the passed in options.
 *
 *********************************************************************/
void processCmdLineOptions(int argc, char *argv[]) {

    int opt;

    // Loop through the command line options.
    while ((opt = getopt_long(argc, argv, "p:vih", long_options, NULL)) != -1) {
        switch (opt) {

            case 'u':
                // Local UDP server port number.
                udpPortNumber = (ushort) atoi(optarg);
                break;

            case 'i':
                // Print IP Header information
                printIPHeaders = true;
                break;

            case 'v':
                // Verbose debugging enable
                printVerboseDebug = true;
                break;

            case 'h':
            default:
                printUsage(argc, argv);
                exit(EXIT_FAILURE);
                break;
        }
    }

    // Default the remote port if it was not specified as an option.
    if (udpPortNumber == 0) {
        udpPortNumber = 55555;
    }
}

/*********************************************************************
 *
 * Function:            main()
 *
 * Description:         Main program loop.
 *                      Process the command line options, Create the TUN,
 *                      Create the UDP Server listener port and wait for
 *                      a connection.
 *
 *********************************************************************/
int main(int argc, char *argv[]) {
    int tunfd, sockfd, retVal;

    // Process the user supplied command line options.
    processCmdLineOptions(argc, argv);

    printf("************************************************************\n");
    printf("VPN Server Initialisation:\n");

    // Set the ip forwarding - sysctl net.ipv4.ip_forward=1
    printf("Auto configuring IP forwarding\n ");
    retVal = system("/sbin/sysctl net.ipv4.ip_forward=1");

    if (retVal != 0) {
        printf("Configuring IP forwarding returned Error code %d\n", retVal);
        exit(EXIT_FAILURE);
    }

    tunfd = createTunDevice();
    sockfd = initUDPServer();

    printf("VPN Server Initialisation Complete.\n");
    printf("************************************************************\n");

    // Enter the main loop
    while (1) {
        fd_set readFDSet;

        FD_ZERO(&readFDSet);
        FD_SET(sockfd, &readFDSet);
        FD_SET(tunfd, &readFDSet);
        select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

        if (FD_ISSET(tunfd, &readFDSet)) tunSelected(tunfd, sockfd);
        if (FD_ISSET(sockfd, &readFDSet)) socketSelected(tunfd, sockfd);
    }
}
 
