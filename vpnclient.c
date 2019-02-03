#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <getopt.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdbool.h>
#include "debug.h"

#define BUFF_SIZE 2000

#define ICMP 1
#define TCP 6
#define UDP 17

bool printVerboseDebug = false;
bool printIPHeaders = false;

static struct option long_options[] =
        {
                {"vpn-server-ip",   required_argument, NULL, 's'},
                {"vpn-server-port", required_argument, NULL, 'p'},
                {"route-network",   required_argument, NULL, 'n'},
                {"route-netmask",   required_argument, NULL, 'm'},
                {"protocol",        required_argument, NULL, '1'},
                {"ip-headers",      no_argument,       NULL, 'i'},
                {"verbose",         no_argument,       NULL, 'v'},
                {"help",            no_argument,       NULL, 'h'},
                {NULL, 0,                              NULL, 0}
        };

char serverIP[17] = "";
char routeIP[17] = "";
char tunIP[17] = "";
char routeNetmask[17] = "";
ushort remotePort;
char protocolType[4] = "";

struct sockaddr_in peerAddr;

/**************************************************************
 *
 * Function:            createTunDevice()
 *
 * Description:         Creates the TUN
 *                      Configures the TUN IP automatically as 10.4.0.1/24
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

    // TODO - Change the local TUN IP to something unique.
    printf("Configuring the '%s' device as %s/24\n", ifr.ifr_name, tunIP);

    // Create the interface configuration command for the new interface name
    sprintf(commandBuffer, "/sbin/ifconfig %s %s/24 up", ifr.ifr_name, tunIP);

    retVal = system(commandBuffer);

    if (retVal != 0) {
        printf("TUN %s interface configuration returned Error code %d\n", ifr.ifr_name, retVal);
        exit(EXIT_FAILURE);
    }

    // Create the route add command for remote network over TUN
    sprintf(commandBuffer, "route add -net %s netmask %s %s", routeIP, routeNetmask, ifr.ifr_name);

    printf("Adding routing information - %s\n", commandBuffer);

    retVal = system(commandBuffer);

    if (retVal != 0) {
        printf("TUN %s route configuration returned Error code %d\n", ifr.ifr_name, retVal);
        exit(EXIT_FAILURE);
    }

    return tunFD;
}

/**************************************************************
 *
 * Function:            connectToUDPServer()
 *
 * Description:         Creates the UDP socket connection to the
 *                      remote VPN server on port 5555
 *
 **************************************************************/
int connectToUDPServer() {

    struct sockaddr_in localAddr;
    int sockFD;
    char *hello = "Connection Request";
    int saLen;
    ssize_t len;
    char buff[17];

    // Create the peer socket address (Internet) structure.
    memset(&peerAddr, 0, sizeof(peerAddr));
    peerAddr.sin_family = AF_INET;
    peerAddr.sin_port = htons(remotePort);
    peerAddr.sin_addr.s_addr = inet_addr(serverIP);

    sockFD = socket(AF_INET, SOCK_DGRAM, 0);

    // Obtain the local socket address information
    saLen = sizeof(localAddr);

    // Send a hello message to "connect" with the VPN server
    sendto(sockFD, hello, strlen(hello), 0,
           (struct sockaddr *) &peerAddr, sizeof(peerAddr));

    if (getsockname(sockFD, (struct sockaddr *) &localAddr, (socklen_t *) &saLen) == -1) {
        perror("getsockname");
        exit(EXIT_FAILURE);
    }

    printf("Opened socket. FD = %d. Bound to IP = %s:%d\n",
           sockFD,
           inet_ntoa(localAddr.sin_addr),
           (int) ntohs(localAddr.sin_port));

    printf("Connected via '%s' to remote server IP/Port:- %s:%d\n", protocolType, serverIP, remotePort);

    // Wait for the server to assign a unique TUN IP address
    len = recvfrom(sockFD, buff, 17, 0,
                   (struct sockaddr *) &peerAddr, &saLen);

    buff[len] = '\0';

    strcpy(tunIP, buff);

    printf("Recevied TUN IP \"%s\" from the server\n", tunIP);

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

    struct iphdr *pIpHeader = (struct iphdr *) buff;

    // Ignore IPv6 packets
    if (pIpHeader->version == 6) {
        return;
    }

    if (printVerboseDebug) {
        printf("TUN->Tunnel- Length:- %d\n", (int) len);
    }

    // Debug output, dump the IP and UDP or TCP headers of the buffer contents.
    if (printIPHeaders) {
        if ((unsigned int) pIpHeader->protocol == UDP) {
            printUDPHeader(buff, (int) len);
        } else if ((unsigned int) pIpHeader->protocol == TCP) {
            printTCPHeader(buff, (int) len);
        } else if ((unsigned int) pIpHeader->protocol == ICMP) {
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
    struct iphdr *pIpHeader = (struct iphdr *) buff;

    bzero(buff, BUFF_SIZE);
    len = recvfrom(sockFD, buff, BUFF_SIZE, 0, (struct sockaddr *) &remoteAddress, &addrSize);

    // Ignore IPv6 packets
    if (pIpHeader->version == 6) {
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
        if ((unsigned int) pIpHeader->protocol == UDP) {
            printUDPHeader(buff, (int) len);
        } else if ((unsigned int) pIpHeader->protocol == TCP) {
            printTCPHeader(buff, (int) len);
        } else if ((unsigned int) pIpHeader->protocol == ICMP) {
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
    fprintf(stdout, " Proof of concept for VPN Client\n\n");
    fprintf(stdout, " Mandatory Options:- \n");
    fprintf(stdout, "   -v --vpn-sever-ip\t\t: Remote VPN Server IP in IPv4 format\n");
    fprintf(stdout, "   -r --route-network\t\t: Remote Network IP to add route for\n");
    fprintf(stdout, "   -m --route-netmask\t\t: Remote Network Netmask used in route add\n");
    fprintf(stdout, "\n Optional Options:- \n");
    fprintf(stdout, "   -p --vpn-server-port\t\t: Remote VPN server Port. Default - 55555 (UDP Port)\n");
    fprintf(stdout, "      --protocol <udp|tcp>\t: VPN protocol (UDP or TCP). Default - UDP\n");
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
    while ((opt = getopt_long(argc, argv, "s:p:n:m:vih", long_options, NULL)) != -1) {
        switch (opt) {
            case 's':
                // Remote server IP. Copy maximum of 16 characters to prevent
                // buffer overflow.
                if (strlen(optarg) <= 16) {
                    sprintf(serverIP, "%s", optarg);
                }
                break;

            case 'p':
                // Remote VPN Server port.
                remotePort = (ushort) atoi(optarg);
                break;

            case 'n':
                // Remote Network IP. Copy maximum of 16 characters to prevent
                // buffer overflow.
                if (strlen(optarg) <= 16) {
                    sprintf(routeIP, "%s", optarg);
                }
                break;

            case 'm':
                // Remote Network Netmask. Copy maximum of 16 characters to prevent
                // buffer overflow.
                if (strlen(optarg) <= 16) {
                    sprintf(routeNetmask, "%s", optarg);
                }
                break;

            case '1':
                // Protocol selection. Copy maximum of 3 characters to prevent
                // buffer overflow.
                if (strlen(optarg) <= 3) {
                    sprintf(protocolType, "%s", optarg);
                }
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
    if (remotePort == 0) {
        remotePort = 55555;
    }

    // Default the protocol type to udp if it was not specified as an option.
    if (protocolType[0] == 0) {
        strcpy(protocolType, "udp");
    }

    // Check for mandatory parameters.
    if ((serverIP[0] == 0) || (routeIP[0] == 0) || (routeNetmask[0] == 0)) {
        // Mandatory option not present. Error and exit
        printUsage(argc, argv);
        exit(EXIT_FAILURE);
    }
}


/*********************************************************************
 *
 * Function:            main()
 *
 * Description:         Main program loop.
 *                      Process the command line options, create
 *                      the TUN, the UDP socket and connect the the
 *                      remote VPN server.
 *
 *********************************************************************/
int main(int argc, char *argv[]) {
    int tunFD, sockFD;

    // Initialise command line argument buffers
    serverIP[0] = '\0';
    routeIP[0] = '\0';
    routeNetmask[0] = '\0';
    remotePort = 0;
    protocolType[0] = '\0';

    // Process the command line options.
    processCmdLineOptions(argc, argv);

    printf("************************************************************\n");
    printf("VPN Client Initialisation:\n");

    sockFD = connectToUDPServer();
    tunFD = createTunDevice();

    printf("VPN Client Initialisation Complete.\n");
    printf("************************************************************\n");

    // Enter the main loop
    while (1) {
        fd_set readFDSet;

        FD_ZERO(&readFDSet);
        FD_SET(sockFD, &readFDSet);
        FD_SET(tunFD, &readFDSet);
        select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

        if (FD_ISSET(tunFD, &readFDSet)) tunSelected(tunFD, sockFD);
        if (FD_ISSET(sockFD, &readFDSet)) socketSelected(tunFD, sockFD);
    }
}
 
