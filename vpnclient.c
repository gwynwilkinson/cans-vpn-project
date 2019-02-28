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
#include <signal.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "tls.h"
#include "debug.h"


#define BUFF_SIZE 2000
#define MAX_IP_ADDRESS_LENGTH 16

#define ICMP 1
#define TCP 6
#define UDP 17

#define CERT_FILE "./certs/client-cert.pem"
#define KEY_FILE  "./certs/client-key.pem"

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
int tunFD, sockFD;

//Function prototypes
void performHandshake(tls_session *pClientSession, int sockFD);

/*****************************************************************************************
 *
 * Function:            createTunDevice()
 *
 * Description:         Creates the TUN
 *                      Configures the TUN IP automatically as 10.4.0.1/24
 *
 *****************************************************************************************/
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

    // Use the IP address returned to us in the connection handshake to configure the IP.
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

/*****************************************************************************************
 *
 * Function:            connectToUDPServer()
 *
 * Description:         Creates the UDP socket connection to the
 *                      remote VPN server on specified port
 *
 *****************************************************************************************/
int connectToUDPServer( tls_session *pClientSession) {

    struct sockaddr_in localAddr;
    int udpSockFD;
    char *hello = "Connection Request";
    socklen_t saLen;
    ssize_t len;
    char buff[17];

    // Create the peer socket address (Internet) structure.
    memset(&peerAddr, 0, sizeof(peerAddr));
    peerAddr.sin_family = AF_INET;
    peerAddr.sin_port = htons(remotePort);
    peerAddr.sin_addr.s_addr = inet_addr(serverIP);

    udpSockFD = socket(AF_INET, SOCK_DGRAM, 0);

    if (udpSockFD == 0) {
        perror("UDP Socket Allocation");
        exit(EXIT_FAILURE);
    }


    // Obtain the local socket address information
    saLen = sizeof(localAddr);

    // Calling connect with UDP socket doesn't send anything, but returns FD
    connect(udpSockFD, (struct sockaddr *) &peerAddr, sizeof(peerAddr));

    if (getsockname(udpSockFD, (struct sockaddr *) &localAddr, &saLen) == -1) {
        perror("getsockname");
        exit(EXIT_FAILURE);
    }

    printf("Opened UDP socket. FD = %d. Bound to IP = %s:%d\n",
           udpSockFD,
           inet_ntoa(localAddr.sin_addr),
           (int) ntohs(localAddr.sin_port));

    printf("Attempting connection to server\n");

    // Perform TLS Handshake
    performHandshake(pClientSession, udpSockFD);

    printf("Attempting connection to server\n");

    // Send the connection request to the server
//    len = send(tcpSockFD, hello, strlen(hello), 0);
    len = SSL_write(pClientSession->ssl, hello, strlen(hello));

    if (len == -1) {
        // Connection error
        perror("UDP Connection Error");
        exit(EXIT_FAILURE);
    }

    // Wait for the server to assign a unique TUN IP address
//    len = recv(tcpSockFD, buff, MAX_IP_ADDRESS_LENGTH, 0);
    len = SSL_read(pClientSession->ssl, buff, MAX_IP_ADDRESS_LENGTH);

    if (len == -1) {
        // Connection error
        perror("UDP Connection Error");
        exit(EXIT_FAILURE);
    } else {
        printf("Connected via '%s' to remote server IP/Port:- %s:%d\n", protocolType, serverIP, remotePort);
    }

    buff[len] = '\0';

    strcpy(tunIP, buff);

    printf("Allocated TUN IP \"%s\" from the server\n", tunIP);

    return udpSockFD;
}


/*****************************************************************************************
 *
 * Function:            connectToTCPServer()
 *
 * Description:         Creates the TCP socket connection to the
 *                      remote VPN server on specified port
 *
 *****************************************************************************************/
int connectToTCPServer(tls_session *pClientSession) {

    struct sockaddr_in localAddr;
    int tcpSockFD;
    char *hello = "Connection Request";
    socklen_t saLen;
    ssize_t len;
    char buff[17];

    // Create the peer socket address (Internet) structure.
    memset(&peerAddr, 0, sizeof(peerAddr));
    peerAddr.sin_family = AF_INET;
    peerAddr.sin_port = htons(remotePort);
    peerAddr.sin_addr.s_addr = inet_addr(serverIP);

    tcpSockFD = socket(AF_INET, SOCK_STREAM, 0);

    if (tcpSockFD == 0) {
        perror("TCP Socket Allocation");
        exit(EXIT_FAILURE);
    }

    // Obtain the local socket address information
    saLen = sizeof(localAddr);

    // Send a server connection request message to "connect" with the VPN server
    if (connect(tcpSockFD, (struct sockaddr *) &peerAddr, sizeof(peerAddr)));

    // Get some info about the local socket
    if (getsockname(tcpSockFD, (struct sockaddr *) &localAddr, &saLen) == -1) {
        perror("getsockname");
        exit(EXIT_FAILURE);
    }

    printf("Opened TCP socket. FD = %d. Bound to IP = %s:%d\n",
           tcpSockFD,
           inet_ntoa(localAddr.sin_addr),
           (int) ntohs(localAddr.sin_port));

    // Perform TLS Handshake
    performHandshake(pClientSession, tcpSockFD);

    printf("Attempting connection to server\n");

    // Send the connection request to the server
//    len = send(tcpSockFD, hello, strlen(hello), 0);
    len = SSL_write(pClientSession->ssl, hello, strlen(hello));

    if (len == -1) {
        // Connection error
        perror("TCP Connection Error");
        exit(EXIT_FAILURE);
    }

    // Wait for the server to assign a unique TUN IP address
//    len = recv(tcpSockFD, buff, MAX_IP_ADDRESS_LENGTH, 0);
    len = SSL_read(pClientSession->ssl, buff, MAX_IP_ADDRESS_LENGTH);

    if (len == -1) {
        // Connection error
        perror("TCP Connection Error");
        exit(EXIT_FAILURE);
    } else {
        printf("Connected via '%s' to remote server IP/Port:- %s:%d\n", protocolType, serverIP, remotePort);
    }

    buff[len] = '\0';

    strcpy(tunIP, buff);

    printf("Allocated TUN IP \"%s\" from the server\n", tunIP);

    return tcpSockFD;

}


/*****************************************************************************************
 *
 * Function:            performHandshake()
 *
 * Description:         Binds the the socket File description to the tls session and
 *                      initiates the handshake.
 *
 *****************************************************************************************/
void performHandshake(tls_session *pClientSession, int sockFD) {

    int sslError;

    printf("Perform Handshake\n");

    /*Bind the socket to the SSL structure*/
    sslError = SSL_set_fd(pClientSession->ssl, sockFD);
    if (sslError != 1) {
        char msg[1024];
        ERR_error_string_n(ERR_get_error(), msg, sizeof(msg));
        printf("%s %s %s %s\n", msg, ERR_lib_error_string(0), ERR_func_error_string(0), ERR_reason_error_string(0));
        exit(EXIT_FAILURE);
    }

    /* Connect to the server, SSL layer.*/
    if (SSL_connect(pClientSession->ssl) != 1) {
        perror("Client SSL_connect");
        exit(EXIT_FAILURE);
    }

    printf("SSL connection is successful\n");
    printf("SSL connection using %s\n", SSL_get_cipher(pClientSession->ssl));
}


/*****************************************************************************************
 *
 * Function:            tunSelected()
 *
 * Description:         Received a packet on the TUN.
 *                      Send to the UDP or TCP socket (tunnel).
 *
 *****************************************************************************************/
void tunSelected(int tunFD, int sockFD, int protocol, SSL *ssl) {
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
        printf("TUN->%s Tunnel- Length:- %d\n",
               protocol == UDP ? "UDP" : "TCP",
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

    // Use the correct method to send depending on the protocol used.
    if (protocol == UDP) {
        /*size = sendto(sockFD, buff, len, 0, (struct sockaddr *) &peerAddr,
                      sizeof(peerAddr));*/
        size = SSL_write(ssl, buff, len);
    } else {
        //size = send(sockFD, buff, len, 0);
        size = SSL_write(ssl, buff, len);
    }

    if (size == 0) {
        perror("sendto");
    }
}

/*****************************************************************************************
 *
 * Function:            socketSelected()
 *
 * Description:         Received a packet on the socket (tunnel).
 *                      Handle either TCP or UDP connection,
 *                      extract the data and send to the TUN
 *                      device (application)
 *
 *****************************************************************************************/
void socketSelected(int tunFD, int sockFD, int protocol, SSL *ssl) {
    ssize_t len;
    char buff[BUFF_SIZE];
    struct sockaddr_storage remoteAddress;
    socklen_t addrSize = sizeof(remoteAddress);
    struct iphdr *pIpHeader = (struct iphdr *) buff;

    bzero(buff, BUFF_SIZE);
    if (protocol == UDP) {
        //len = recvfrom(sockFD, buff, BUFF_SIZE, 0, (struct sockaddr *) &remoteAddress, &addrSize);
        len = SSL_read(ssl, buff, BUFF_SIZE);
    } else {
        //len = recv(sockFD, buff, BUFF_SIZE, 0);
        len = SSL_read(ssl, buff, BUFF_SIZE);
        // Get the peer address info
        getpeername(sockFD, (struct sockaddr *) &remoteAddress, &addrSize);
    }

    if (len == -1) {
        if (protocol == UDP) {
            perror("UDP socket recv error");
        } else {
            perror("TCP socket recv error");
        }
        return;
    } else if (len == 0) {
        // Connection has been closed. Quit.
        printf("Server has closed the connection\n");
        close(sockFD);
        exit(EXIT_SUCCESS);
    }

    // Ignore IPv6 packets
    if (pIpHeader->version == 6) {
        return;
    }

    if (printVerboseDebug) {
        printf("%s Tunnel->TUN - Source IP %s:%d - Length %d\n",
               protocol == UDP ? "UDP" : "TCP",
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

/*****************************************************************************************
 *
 * Function:            printUsage()
 *
 * Description:         Display the help for the command line option.
 *
 *****************************************************************************************/
void printUsage(int argc, char *argv[]) {
    fprintf(stdout, "\n Usage: %s [options]\n\n", argv[0]);
    fprintf(stdout, " Proof of concept for VPN Client\n\n");
    fprintf(stdout, " Mandatory Arguments:- \n");
    fprintf(stdout, "   -s --vpn-server-ip\t\t: Remote VPN Server IP in IPv4 format\n");
    fprintf(stdout, "   -n --route-network\t\t: Remote Network IP to add route for\n");
    fprintf(stdout, "   -m --route-netmask\t\t: Remote Network Netmask used in route add\n");
    fprintf(stdout, "\n Optional Arguments:- \n");
    fprintf(stdout, "   -p --vpn-server-port\t\t: Remote VPN server Port. Default - 55555 (UDP Port)\n");
    fprintf(stdout, "      --protocol <udp|tcp>\t: VPN protocol (UDP or TCP). Default - UDP\n");
    fprintf(stdout, "   -v --verbose\t\t\t: Verbose debug logging. Dumps packet headers to stdout\n");
    fprintf(stdout, "   -i --ip-headers\t\t: Print out IP headers\n");
    fprintf(stdout, "   -h --help\t\t\t: Help\n");
    fprintf(stdout, "\n");
}


/*****************************************************************************************
 *
 * Function:            processCmdLineOptions()
 *
 * Description:         Process the command line options and setup
 *                      the variables based on the passed in options.
 *
 *****************************************************************************************/
void processCmdLineOptions(int argc, char *argv[]) {

    int opt;

    // Loop through the command line options.
    while ((opt = getopt_long(argc, argv, "s:p:n:m:vih", long_options, NULL)) != -1) {
        switch (opt) {
            case 's':
                // Remote server IP. Copy maximum of 16 characters to prevent
                // buffer overflow.
                if (strlen(optarg) <= MAX_IP_ADDRESS_LENGTH) {
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
                if (strlen(optarg) <= MAX_IP_ADDRESS_LENGTH) {
                    sprintf(routeIP, "%s", optarg);
                }
                break;

            case 'm':
                // Remote Network Netmask. Copy maximum of 16 characters to prevent
                // buffer overflow.
                if (strlen(optarg) <= MAX_IP_ADDRESS_LENGTH) {
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

    // Default the protocol type to udp if it was not specified as an option.
    if (protocolType[0] == 0) {
        strcpy(protocolType, "udp");
    } else {
        // Verify that the protocol was set to 'udp' or 'tcp'.
        if (strcmp(protocolType, "udp") != 0 && strcmp(protocolType, "tcp") != 0) {
            // An invalid protocol type was specified. Error and quit
            fprintf(stderr, "Invalid protocol type specified. Must be 'udp' or 'tcp'\n");
            printUsage(argc, argv);
            exit(EXIT_FAILURE);
        }
    }

    // Default the remote port if it was not specified as an option.
    if (remotePort == 0) {
        if (strcmp(protocolType, "udp") == 0) {
            // Default the port for UDP
            remotePort = 55555;
        } else {
            // Default the port for TCP
            remotePort = 44444;
        }
    }

    // Check for mandatory parameters.
    if ((serverIP[0] == 0) || (routeIP[0] == 0) || (routeNetmask[0] == 0)) {
        // Mandatory option not present. Error and exit
        printUsage(argc, argv);
        exit(EXIT_FAILURE);
    }
}

/*****************************************************************************************
 *
 * Function:            sigIntHandler()
 *
 * Description:         SIGINT Handler for sending a client termination message to the
 *                      server so that it can remove the UDP instance from its list.
 *
 *****************************************************************************************/
void sigIntHandler(int sig) {

    char buff[] = "Terminate UDP Connection";
    ssize_t size;
    int len = sizeof(buff);

    // Report that this signal can be ignored. We are handling it here.
    signal(sig, SIG_IGN);

    printf("\nCntrl-C pressed. Terminating connection to VPN server\n");

    // Write the packet to the TUN device.
    size = write(tunFD, buff, (size_t) len);

    sendto(sockFD, buff, len, 0, (struct sockaddr *) &peerAddr,
           sizeof(peerAddr));

    if (size == 0) {
        perror("sendto");
    }

    sleep(1);

    exit(EXIT_SUCCESS);
}

/*****************************************************************************************
 *
 * Function:            main()
 *
 * Description:         Main program loop.
 *                      Process the command line options, create
 *                      the TUN, the UDP socket and connect the the
 *                      remote VPN server.
 *
 *****************************************************************************************/
int main(int argc, char *argv[]) {

    struct sigaction sa;
    int protocol;
    int sslError;
    tls_session clientSession;

    bzero(&clientSession, sizeof(tls_session));

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

    // Set a local value for the protocol type so we do not have
    // to keep doing an expensive string compare.
    if (strcmp(protocolType, "udp") == 0) {
        protocol = UDP;
    } else {
        protocol = TCP;
    }

    // Initialise the (D)TLS context based on the specified protocol
    if (tls_init(&clientSession, false, protocol, SSL_VERIFY_NONE, serverIP, CERT_FILE, KEY_FILE) == -1) {
        perror("Client tls_init");
        exit(EXIT_FAILURE);
    }


    // Client can be either UDP or TCP, start the correct connection
    if (protocol == UDP) {
        sockFD = connectToUDPServer(&clientSession);

        // For UDP we need to trap any Ctrl-C so that we can send a termination
        // message to the server so that they can clean up resources on their end
        sa.sa_handler = sigIntHandler;
        sigemptyset(&sa.sa_mask);

        if (sigaction(SIGINT, &sa, NULL) == -1) {
            perror("Server sigaction");
            exit(EXIT_FAILURE);
        }
    } else {
        sockFD = connectToTCPServer(&clientSession);
    }

    // Create the TUN device
    tunFD = createTunDevice();

    printf("VPN Client Initialisation Complete.\n");
    printf("************************************************************\n");

    // Enter the main loop
    while (1) {
        fd_set readFDSet;

        FD_ZERO(&readFDSet);

        // Client can only be either UDP or TCP. Insert the correct
        if (protocol == UDP) {
            FD_SET(sockFD, &readFDSet);
        } else {
            FD_SET(sockFD, &readFDSet);
        }

        FD_SET(tunFD, &readFDSet);

        select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

        if (FD_ISSET(tunFD, &readFDSet)) tunSelected(tunFD, sockFD, protocol, clientSession.ssl);

        if (protocol == UDP) {
            if (FD_ISSET(sockFD, &readFDSet)) socketSelected(tunFD, sockFD, UDP, clientSession.ssl);
        } else {
            if (FD_ISSET(sockFD, &readFDSet)) socketSelected(tunFD, sockFD, TCP, clientSession.ssl);
        }
    }
}
