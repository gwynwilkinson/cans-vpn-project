#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdbool.h>
#include <getopt.h>
#include <wait.h>
#include <json-c/json.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include "tls.h"
#include "debug.h"
#include "list.h"
#include "logging.h"
#include "vpnserver.h"

#define BUFF_SIZE 2000
#define MAX_CLIENTS 250
#define PENDING_CONNECTIONS 5


#define CERT_FILE "./certs/vpn-cert.pem"
#define KEY_FILE  "./certs/vpn-key.pem"

// Global variables
bool printVerboseDebug = false;
bool printIPHeaders = false;
bool udpClientConnected = false;

// Definitions for command line options
static struct option long_options[] =
        {
                {"udp-server-port", required_argument, NULL, 'u'},
                {"tcp-server-port", required_argument, NULL, 't'},
                {"ip-headers",      no_argument,       NULL, 'i'},
                {"verbose",         no_argument,       NULL, 'v'},
                {"help",            no_argument,       NULL, 'h'},
                {NULL, 0,                              NULL, 0}
        };

// Store for server port numbers
ushort udpPortNumber = 0;
ushort tcpPortNumber = 0;

// Global variable for the IP lookup linked list.
struct listEntry *pHead = NULL;

// Array storing assigned client IP addresses in the range 10.4.0.x
bool clientIPAddress[MAX_CLIENTS] = {false};

// Management client TLS structure and connection FD
int mgmtConnectionFD = 0;
tlsSession *pMgmtClientTLSSession;

// A PIPE used by the child to send data back to the Parent server process
// indicating that the child is terminating. This allows the parent server
// to clean up the linked list after a child dies
int childParentPipe[2];

/**********************************************************************************************************************
 *
 * Initialisation functions
 *
 **********************************************************************************************************************/

/*****************************************************************************************
 *
 * Function:            uniqueClientIPAddress()
 *
 * Description:         Returns the next free client IP Address
 *                      in the 10.4.0.1 -> 10.4.0.250
 *
 *****************************************************************************************/
void uniqueClientIPAddress(char *pIpAddress) {

    int i;

    // Loop through the free client array
    for (i = 1; i < MAX_CLIENTS; i++) {
        if (clientIPAddress[i] == false) {
            sprintf(pIpAddress, "10.4.0.%d", i);
            clientIPAddress[i] = true;
            return;
        }
    }

    // No free clients. Null the string.
    pIpAddress[0] = '\0';
}

/*****************************************************************************************
 *
 * Function:            createTunDevice()
 *
 * Description:         Creates the TUN
 *                      Configures the TUN IP automatically as 10.4.0.250/24
 *
 *****************************************************************************************/
int createTunDevice() {

    struct ifreq ifr;
    int tunFD;
    int retVal = 0;
    char *v[5];
    int pid;
    pid_t c;

    // Zero the structure
    memset(&ifr, 0, sizeof(ifr));

    // Set the TUN flags and open the device
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    tunFD = open("/dev/net/tun", O_RDWR);
    if (tunFD == -1) {
        LOG(BOTH, "Error opening TUN device!\n");
        return 0;
    }

    // Get the TUN interface info
    ioctl(tunFD, TUNSETIFF, &ifr);

    LOG(BOTH, "TUN %s created with FD = %d\n", ifr.ifr_name, tunFD);
    LOG(BOTH, "Configuring the %s device as 10.4.0.250/24\n", ifr.ifr_name);

    // Configure the interface for the correct tun device.
    v[0] = "/sbin/ifconfig";
    v[1] = (char *) &ifr.ifr_name;
    v[2] = "10.4.0.250/24";
    v[3] = "up";
    v[4] = 0;

    // Need to for off for the execve
    if ((pid = fork()) == 0) {
        // Child process
        retVal = execve(v[0], v, 0);
    } else {
        // Wait for the child to exit.
        c = wait(NULL);
    }

    if (retVal != 0) {
        LOG(BOTH, "TUN %s interface configuration returned Error code %d\n", ifr.ifr_name, retVal);
        exit(EXIT_FAILURE);
    }

    // File logging - Report TUN creation
    LOG(LOGFILE, "TUN %s interface configuration completed successfully\n", ifr.ifr_name);

    return (tunFD);
}

/*****************************************************************************************
 *
 * Function:            initUDPServer()
 *
 * Description:         Initialises the UDP server listener on
 *                      the Local UDP server port.
 *
 *****************************************************************************************/
int initUDPServer() {
    struct sockaddr_in server;
    struct sockaddr_in localAddr;
    int udpSockFD = 0;
    socklen_t saLen = sizeof(struct sockaddr_in);;

    // Create a local server sockaddr_in structure to bind to
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(udpPortNumber);

    // Create a UDP socket for the listener
    udpSockFD = socket(AF_INET, SOCK_DGRAM, 0);

    if (udpSockFD == 0) {
        perror("UDP Socket Allocation");
        exit(EXIT_FAILURE);
    }

    // Bind to the socket
    bind(udpSockFD, (struct sockaddr *) &server, sizeof(server));

    if (getsockname(udpSockFD, (struct sockaddr *) &localAddr, &saLen) == -1) {
        perror("getsockname");
        exit(EXIT_FAILURE);
    }

    // Report UDP socket creation
    LOG(BOTH, "Created UDP socket. FD = %d. Bound to IP = %s:%d\n",
        udpSockFD,
        inet_ntoa(localAddr.sin_addr),
        (int) ntohs(localAddr.sin_port));


    return (udpSockFD);
}

/*****************************************************************************************
 *
 * Function:            initTCPServer()
 *
 * Description:         Initialises a  TCP server listener on
 *                      the given port.
 *
 *                      This function is reused for the main TCP
 *                      tunnel server listener, and also for the
 *                      mgmt client interface.
 *
 *****************************************************************************************/
int initTCPServer(int portNumber) {

    struct sockaddr_in server;
    struct sockaddr_in localAddr;
    int tcpSockFD = 0;
    int yes = 1;
    socklen_t saLen = sizeof(struct sockaddr_in);;

    tcpSockFD = socket(AF_INET, SOCK_STREAM, 0);

    if (tcpSockFD == 0) {
        perror("TCP Socket allocation");
        exit(EXIT_FAILURE);
    }

    /* Set Unix socket level to allow address reuse */
    if (setsockopt(tcpSockFD, SOL_SOCKET, SO_REUSEADDR,
                   &yes, sizeof(int)) == -1) {
        perror("Server setsockopt");
        exit(EXIT_FAILURE);
    }

    // Create a local server sockaddr_in structure to bind to
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(portNumber);

    // Bind to the socket
    bind(tcpSockFD, (struct sockaddr *) &server, sizeof(server));

    if (getsockname(tcpSockFD, (struct sockaddr *) &localAddr, &saLen) == -1) {
        perror("getsockname");
        exit(EXIT_FAILURE);
    }

    // Logging - Report TCP socket creation
    LOG(BOTH, "Created TCP socket. FD = %d. Bound to IP = %s:%d\n",
        tcpSockFD,
        inet_ntoa(localAddr.sin_addr),
        (int) ntohs(localAddr.sin_port));

    // Listen on the port
    if (listen(tcpSockFD, PENDING_CONNECTIONS) == -1) {
        perror("TCP Server listen");
        exit(EXIT_FAILURE);
    }

    // Create a PIPE for child TCP process -> parent communication
    pipe(childParentPipe);

    return (tcpSockFD);
}

/**********************************************************************************************************************
 *
 * TUN handling functions
 *
 **********************************************************************************************************************/

/*****************************************************************************************
 *
 * Function:            tunSelected()
 *
 * Description:         Received a packet on the TUN.
 *                      Send to the UDP socket (tunnel), or send
 *                      to the correct PIPE for the TCP child
 *                      process serving this destination IP
 *
 *****************************************************************************************/
void tunSelected(int tunFD) {

    char buff[BUFF_SIZE];
    struct sockaddr_in destAddr;
    struct sockaddr_in *pPeerAddr;
    struct iphdr *pIpHeader = (struct iphdr *) buff;
    tlsSession *pTLSSession;
    int protocol;
    int connectionFD;
    int pipeFD;
    ssize_t len, size;

    // Initialise the buffer and read the data from the TUN
    bzero(buff, BUFF_SIZE);
    len = read(tunFD, buff, BUFF_SIZE);
    if ((len == 0) || (len == -1)) {
        // Error reading from the TUN. Quit.
        perror("TUN read error");
        exit(EXIT_FAILURE);
    }

    // Ignore IPv6 packets
    if (pIpHeader->version == 6) {
        return;
    }

    // Perform the peer socket address lookup in the linked list
    // based on the destination address in the buffer.
    destAddr.sin_addr.s_addr = pIpHeader->daddr;
    destAddr.sin_family = AF_INET;

    // Obtain the peerAddress structure (Used for UDP) and the PIPE FD (Used for TCP)
    // for this destination TUN IP address and set the protocol variable so that we can determine
    // which method to use later.
    pPeerAddr = findByTUNIPAddress(inet_ntoa(destAddr.sin_addr), &protocol, &pipeFD, &connectionFD, &pTLSSession);

    if (printVerboseDebug) {
        LOG(SCREEN, "TUN->%s Tunnel- Length:- %d\n",
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

    if (pPeerAddr == NULL) {
        LOG(BOTH, "!!!!ERROR!!!! - tunSelected() could not find peer address structure for dest IP %s\n\n",
            inet_ntoa(destAddr.sin_addr));
        return;
    }

    // For UDP, the server will send the data to the client directly.
    // For TCP, send the data to the correct child process via the PIPE
    if (protocol == UDP) {
        // Send the message to the correct peer.
        size = SSL_write(pTLSSession->ssl, buff, len);

    } else {
        // Connection FD for TCP is the PIPE FD.
        size = write(pipeFD, buff, (size_t) len);
    }

    if (size == 0) {
        perror("sendto");
    }
}


/**********************************************************************************************************************
 *
 * UDP tunnel functions
 *
 **********************************************************************************************************************/

/*****************************************************************************************
 *
 * Function:            udpSocketSelected()
 *
 * Description:         Received a packet on the UDP socket (tunnel).
 *                      If it is a new connection, perform the TLS handshake, otherwise
 *                      send the data to the TUN device (application)
 *
 *****************************************************************************************/
void udpSocketSelected(int tunFD, int udpSockFD, int tcpSockFD, int mgmtSockFD, SSL_CTX *dtls_ctx) {
    ssize_t len;
    char buff[BUFF_SIZE];
    struct sockaddr_in *pPeerAddr;
    struct iphdr *pIpHeader = (struct iphdr *) buff;
    socklen_t addrSize = sizeof(struct sockaddr_in);
    int err;
    char *errstr;
    tlsSession *pTLSSession;

    bzero(buff, BUFF_SIZE);

    // Only a single UDP client can be connected at a time
    if (udpClientConnected == false) {
        LOG(BOTH, "New Incoming UDP connection\n");

        // Allocate the memory for the peerAddr structure
        pPeerAddr = (struct sockaddr_in *) malloc(sizeof(struct sockaddr_in));

        // Verify the memory was allocated
        if (pPeerAddr == NULL) {
            perror("malloc");
            exit(EXIT_FAILURE);
        }

        // Allocate the memory for a new TLS Session structure
        pTLSSession = (tlsSession *) malloc(sizeof(tlsSession));

        // Verify the memory was allocated
        if (pTLSSession == NULL) {
            perror("malloc");
            exit(EXIT_FAILURE);
        } else {
            bzero(pTLSSession, sizeof(tlsSession));
        }

        struct timeval timeout;

        // Create a new SSL connection object
        pTLSSession->ssl = SSL_new(dtls_ctx);

        SSL_CTX_set_cookie_generate_cb(dtls_ctx, generate_cookie);
        SSL_CTX_set_cookie_verify_cb(dtls_ctx, &verify_cookie);

        pTLSSession->bio = BIO_new_dgram(udpSockFD, BIO_NOCLOSE);

        /* Set and activate timeouts */
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;
        BIO_ctrl(pTLSSession->bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

        SSL_set_bio(pTLSSession->ssl, pTLSSession->bio, pTLSSession->bio);
        SSL_set_options(pTLSSession->ssl, SSL_OP_COOKIE_EXCHANGE);

        int ret = DTLSv1_listen(pTLSSession->ssl, (BIO_ADDR *) pPeerAddr);

        if (ret < 0) {
            char msg[1024];
            ERR_error_string_n(ERR_get_error(), msg, sizeof(msg));
            printf("%s %s %s %s\n", msg, ERR_lib_error_string(0), ERR_func_error_string(0), ERR_reason_error_string(0));

        }

        // TODO - examine error code 0 being thrown by SSL_accept when client times out (if we have time)
        // Complete the handshake
        ret = SSL_accept(pTLSSession->ssl);
        if (ret <= 0) {
            //TODO - this prints error strings for unsuccessful handshakes (correct behaviour) - fix if time?
            //TODO - double errors after failed handshake - auto-retry causes packets to be out of order?
            char msg[1024];
            ERR_error_string_n(ERR_get_error(), msg, sizeof(msg));
            printf("%s %s %s %s\n", msg, ERR_lib_error_string(0), ERR_func_error_string(0), ERR_reason_error_string(0));
            free(pTLSSession);
            free(pPeerAddr);
            return;
        }

        //  /* Tell openssl to process the packet now stored in the bio */
        err = SSL_read(pTLSSession->ssl, buff, BUFF_SIZE);
        if (err <= 0) {
            char msg[1024];
            ERR_error_string_n(ERR_get_error(), msg, sizeof(msg));
            printf("%s %s %s %s\n", msg, ERR_lib_error_string(0), ERR_func_error_string(0), ERR_reason_error_string(0));
            free(pTLSSession);
            free(pPeerAddr);
            return;
        }

        if (strncmp("Connection Request", buff, 18) == 0) {
            LOG(BOTH, "New UDP client connection from %s:%d.\n",
                inet_ntoa(pPeerAddr->sin_addr),
                ntohs(pPeerAddr->sin_port));

            // Send back to the client a unique IP address.
            uniqueClientIPAddress(buff);

            // Ensure we got a client address
            if (buff[0] != '\0') {
                // Send the buffer to the TCP socket
                int size = SSL_write(pTLSSession->ssl, buff, (int) strlen(buff));

                if (size == 0) {
                    // Error sending data
                    perror("TCP socket send");
                }

                if (printVerboseDebug) {
                    LOG(SCREEN, "Assigned IP %s to client\n", buff);
                }

                LOG(SCREEN, "**********************************************************\n");

                // Pass 0 for Pipe FD and Child process PID. Not used for UDP.
                insertTail(buff, UDP, pPeerAddr, 0, udpSockFD, 0, pTLSSession);

                // Mark that we have a UDP client connected
                udpClientConnected = true;
            }
        }
    } else {
        // Client already connected, Check if its a termination message.
        pTLSSession = findUDPSession(&pPeerAddr);

        if (pTLSSession == NULL) {
            // Logic error. We have an internal flag that a UDP client is connected, but
            // we cannot find the session structure for it. This should not happen. Clean up the
            // data
            LOG(SCREEN, "Error, UDP client information not found\n");
            udpClientConnected = false;
            return;

        }

        // Read the TLS info into the buffer
        len = SSL_read(pTLSSession->ssl, buff, BUFF_SIZE);
        if (len < 0) {
            char msg[1024];
            ERR_error_string_n(ERR_get_error(), msg, sizeof(msg));
            printf("%s %s %s %s\n", msg, ERR_lib_error_string(0), ERR_func_error_string(0), ERR_reason_error_string(0));
        }

        if (strncmp("Terminate UDP Connection", buff, 24) == 0) {
            LOG(BOTH, "UDP client %s:%d terminating \n",
                inet_ntoa(pPeerAddr->sin_addr),
                ntohs(pPeerAddr->sin_port));
            LOG(SCREEN, "**********************************************************\n");

            // Delete the child process entry from the linked list
            deleteEntryByPeerAddr(pPeerAddr);

            // Indicate no connected UDP client.
            udpClientConnected = false;

            // Entry cleaned up, return from the function.
            return;
        }

        // Ignore IPv6 packets
        if (pIpHeader->version == 6) {
            return;
        }

        if (printVerboseDebug) {
            LOG(SCREEN, "UDP Tunnel->TUN - Source IP %s:%d - Length %d\n",
                inet_ntoa(pPeerAddr->sin_addr),
                (int) ntohs(pPeerAddr->sin_port),
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
}

/**********************************************************************************************************************
 *
 * TCP tunnel functions
 *
 **********************************************************************************************************************/

/*****************************************************************************************
 *
 * Function:            readChildPIPE()
 *
 * Description:         The TUN (application) is trying to send
 *                      a packet to the tunnel. Receive the
 *                      data from the PIPE and send to the
 *                      TCP tunnel FD
 *
 *****************************************************************************************/
void readChildPIPE(int pipeFD) {

    char buff[BUFF_SIZE];
    struct iphdr *pIpHeader = (struct iphdr *) buff;
    struct sockaddr_in destAddr;
    struct sockaddr_in *pPeerAddr = NULL;
    ssize_t len, size;
    tlsSession *pTLSSession;
    int connectionFD;
    int protocol;

    // Read the data from the PIPE (TUN)
    len = read(pipeFD, buff, BUFF_SIZE);

    if (len == 0) {
        perror("PIPE read error");
        exit(EXIT_FAILURE);
    }

    // Perform the peer socket address lookup in the linked list
    // based on the TUN destination address in the buffer.
    destAddr.sin_addr.s_addr = pIpHeader->daddr;
    destAddr.sin_family = AF_INET;

    // Obtain the TLS Session structures for this destination IP
    pPeerAddr = findByTUNIPAddress(inet_ntoa(destAddr.sin_addr), &protocol, &pipeFD, &connectionFD, &pTLSSession);

    if (pPeerAddr == NULL) {
        LOG(BOTH, "readChildPIPE() Unable to find TUN IP Address %s\n", inet_ntoa(destAddr.sin_addr));
    }

    // Send the buffer to the TCP socket
    size = SSL_write(pTLSSession->ssl, buff, (int) len);

    if (size == 0) {
        // Error sending data
        perror("Tunnel socket send");
    }
}


/*****************************************************************************************
 *
 * Function:            readChildTCPSocket()
 *
 * Description:         Received a packet on the child TCP socket (tunnel)
 *                      Send to the TUN device (application)
 *
 *****************************************************************************************/
void readChildTCPSocket(int tunFD, int connectionFD, struct sockaddr_in *pPeerAddr, int pipeFD,
                        tlsSession *pTLSSession) {

    char buff[BUFF_SIZE];
    struct iphdr *pIpHeader = (struct iphdr *) buff;
    ssize_t len;

    // Read the data from the tunnel socket
    len = SSL_read(pTLSSession->ssl, buff, BUFF_SIZE);
    if (len == -1) {
        perror("Child server TCP recv");
        close(connectionFD);
        close(pipeFD);
        exit(EXIT_FAILURE);
    } else if (len == 0) {
        // Connection has been closed. Kill the connection and
        // child process
        // File Logging - Report TCP Client termination

        // Find the unique remote TUN IP address in the linked list structure
        // using the Peer IP and Port as a lookup.
        strcpy(buff, findByPeerIPAddress(pPeerAddr, &pTLSSession));

        write(childParentPipe[1], buff, strlen(buff));

        LOG(BOTH, "TCP Client %s:%d has closed the connection.\n",
            inet_ntoa(pPeerAddr->sin_addr),
            ntohs(pPeerAddr->sin_port));
        LOG(SCREEN, "**********************************************************\n");

        if (printVerboseDebug) {
            printf("Killing Child PID %d - Closing connection FD %d \n", (int) getpid(), connectionFD);
            printf("CHILD - Sending death of remote TUN IP %s to parent\n", buff);
        }

        close(connectionFD);
        close(pipeFD);

        exit(EXIT_SUCCESS);
    }

    // Ignore IPv6 packets
    if (pIpHeader->version == 6) {
        return;
    }

    if (printVerboseDebug) {
        LOG(SCREEN, "TCP Tunnel->TUN - Source IP %s:%d - Length %d\n",
            inet_ntoa(pPeerAddr->sin_addr),
            (int) ntohs(pPeerAddr->sin_port),
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
 * Function:            vpnChildSubProcess()
 *
 * Description:         Subroutine to handle the main loop for the
 *                      VPN TCP socket child process.
 *
 *****************************************************************************************/
void vpnTCPChildSubProcess(int udpSockFD, int tcpSockFD, int mgmtSockFD, struct sockaddr_in *pPeerAddr,
                           int pipeFD[], int connectionFD, int tunFD, tlsSession *pTLSSession) {

    // This is the child instance of the server. Close down the TCP
    // server listener port, UDP port. We will only be concerned with
    // dealing with this TCP connection from now on.
    close(udpSockFD);
    close(tcpSockFD);
    close(mgmtSockFD);

    // Close the child write end of the pipe
    close(pipeFD[1]);

    if (printVerboseDebug) {
        LOG(SCREEN, "Spawned child server process PID-%d for connection FD:%d\n", getpid(), connectionFD);
    }

    // Set up a new loop to listen to the connection FD only. The
    // parent process will deal with TUN->Tunnel packets.
    while (1) {
        fd_set readFDSet;

        FD_ZERO(&readFDSet);
        FD_SET(connectionFD, &readFDSet);
        FD_SET(pipeFD[0], &readFDSet);

        select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

        if (FD_ISSET(pipeFD[0], &readFDSet)) readChildPIPE(pipeFD[0]);
        if (FD_ISSET(connectionFD, &readFDSet))
            readChildTCPSocket(tunFD, connectionFD, pPeerAddr, pipeFD[0], pTLSSession);
    }
}

/*****************************************************************************************
 *
 * Function:            tcpListenerSocketSelected()
 *
 * Description:         Received a packet on the TCP socket (tunnel)
 *                      Allocate a new TUN IP for the client and then
 *                      spawn a new child process to handle
 *                      future data from this connection
 *
 *****************************************************************************************/
void tcpListenerSocketSelected(int tunFD, int tcpSockFD, int udpSockFD, int mgmtSockFD, SSL_CTX *tls_ctx) {
    ssize_t len;
    char buff[BUFF_SIZE];
    struct sockaddr_in *pPeerAddr;
    struct iphdr *pIpHeader = (struct iphdr *) buff;
    socklen_t addrSize = sizeof(struct sockaddr_in);
    tlsSession *pTLSSession;
    int connectionFD;
    int pipeFD[2];
    int pid;
    int err;

    bzero(buff, BUFF_SIZE);

    // Allocate the memory for the peerAddr structure
    pPeerAddr = (struct sockaddr_in *) malloc(sizeof(struct sockaddr_in));

    // Verify the memory was allocated
    if (pPeerAddr == NULL) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    // Accept the new incoming connection
    connectionFD = accept(tcpSockFD, (struct sockaddr *) pPeerAddr, &addrSize);

    if (connectionFD == -1) {
        perror("Error accepting TCP connection");
        return;
    }

    if (printVerboseDebug) {
        LOG(SCREEN, "Connection FD for new connection is %d\n", connectionFD);
    }

    // Allocate the memory for a new TLS Session structure
    if ((pTLSSession = (tlsSession *) malloc(sizeof(tlsSession))) == NULL) {
        // Memory allocation error
        perror("malloc");
        free(pPeerAddr);
        exit(EXIT_FAILURE);
    } else {
        bzero(pTLSSession, sizeof(tlsSession));
    }

    // Create a new ssl object
    if ((pTLSSession->ssl = SSL_new(tls_ctx)) == NULL) {
        perror("Error creating TCP SSL structure.");
        free(pPeerAddr);
        free(pTLSSession);
        return;
    }

    // Bind the ssl object with the socket
    SSL_set_fd(pTLSSession->ssl, connectionFD);

    //TODO - this prints error strings for unsuccessful handshakes (correct behaviour) - fix if time?

    // Perform the SSL Handshake
    if (SSL_accept(pTLSSession->ssl) == -1) {
        // Handshake error
        char msg[1024];
        ERR_error_string_n(ERR_get_error(), msg, sizeof(msg));
        printf("%s %s %s %s\n", msg, ERR_lib_error_string(0), ERR_func_error_string(0), ERR_reason_error_string(0));
        free(pPeerAddr);
        free(pTLSSession);
        return;
    }

    len = SSL_read(pTLSSession->ssl, buff, BUFF_SIZE - 1);

    if (len == -1) {
        // This shouldnt really happen. Close the connection FD anyway
        close(connectionFD);
        char msg[1024];
        ERR_error_string_n(ERR_get_error(), msg, sizeof(msg));
        printf("%s %s %s %s\n", msg, ERR_lib_error_string(0), ERR_func_error_string(0), ERR_reason_error_string(0));
        free(pPeerAddr);
        free(pTLSSession);

        return;
    } else if (len == 0) {
        // This shouldnt really happen. Close the connection FD anyway
        free(pPeerAddr);
        free(pTLSSession);
        close(connectionFD);
        return;
    }

    // Check if its a new client connection
    // File Logging - Report new TCP VPN connection
    if (strncmp("Connection Request", buff, 18) == 0) {
        LOG(BOTH, "New TCP client connection from %s:%d.\n",
            inet_ntoa(pPeerAddr->sin_addr),
            ntohs(pPeerAddr->sin_port));

        // Determine and send back to the client a unique IP address.
        uniqueClientIPAddress(buff);

        // Ensure we got a client address
        if (buff[0] != '\0') {
            len = SSL_write(pTLSSession->ssl, buff, strlen(buff));
            //len = send(connectionFD, buff, strlen(buff), 0);

            if (len == -1) {
                perror("SSL Send error");
                LOG(LOGFILE, "SSL Send error.");
                return;
            }

            if (printVerboseDebug) {
                LOG(BOTH, "Assigned IP %s to client\n", buff);
            } else {
                LOG(LOGFILE, "Assigned IP %s to client\n", buff);
            }

            LOG(SCREEN, "**********************************************************\n");
        }

        // Create a PIPE for communication between parent/child
        pipe(pipeFD);

        if (printVerboseDebug) {
            LOG(BOTH, "Created PIPE with FDs [%d] and [%d]\n", pipeFD[0], pipeFD[1]);
        } else {
            LOG(LOGFILE, "Created PIPE with FDs [%d] and [%d]\n", pipeFD[0], pipeFD[1]);
        }


        // Fork a new server instance to deal with this TCP connection
        if ((pid = fork()) == 0) {
            // This is the Child process
            // The Child process needs to add the entry to the linked list so that it
            // can perform lookups and find the TLS Session associated to the TUNIP, etc.
            // This code cannot be performed before the fork as the parent process requires
            // the PID of the Child process to be stored (so that the VPN manager is able
            // to terminate the session.
            insertTail(buff, TCP, pPeerAddr, pipeFD[1], connectionFD, pid, pTLSSession);

            // Handle the child process sub-function
            vpnTCPChildSubProcess(udpSockFD, tcpSockFD, mgmtSockFD, pPeerAddr, pipeFD, connectionFD, tunFD,
                                  pTLSSession);

        } else {
            // This is the Parent process
            // Add the peer address structure to the linked list and store the pipeFD
            // so that the parent process can determine which child needs to handle
            // the TUN->tunnel communication.
            insertTail(buff, TCP, pPeerAddr, pipeFD[1], connectionFD, pid, pTLSSession);

            // Parent does not need the connection FD
            close(connectionFD);
            close(pipeFD[0]);
        }
    } else {
        // Error. We should only be receiving new connection requests on this socket FD.
        if (printVerboseDebug) {
            LOG(BOTH, "Error! - Data (not a connection request) received on TCP Listener socket from %s:%d\n",
                inet_ntoa(pPeerAddr->sin_addr),
                ntohs(pPeerAddr->sin_port));
        } else {
            LOG(LOGFILE, "Error! - Data (not a connection request) received on TCP Listener socket from %s:%d\n",
                inet_ntoa(pPeerAddr->sin_addr),
                ntohs(pPeerAddr->sin_port));
        }

        close(connectionFD);
    }
}

/**********************************************************************************************************************
 *
 * Management Client functions
 *
 **********************************************************************************************************************/

/*****************************************************************************************
 *
 * Function:            mgmtClientSocket()
 *
 * Description:         Subroutine to handle the main loop for the
 *                      Management client once it has connected.
 *
 *****************************************************************************************/
void mgmtClientSocket(int connectionFD) {

    json_object *jParsedJson;
    json_object *jStringRequestType;

    char buff[BUFF_SIZE];
    ssize_t len;

    bzero(buff, BUFF_SIZE);

    len = SSL_read(pMgmtClientTLSSession->ssl, buff, BUFF_SIZE - 1);

    if ((len == 0) || (len == -1)) {
        // Connection has been closed. Close the port and kill the process
        LOG(BOTH, "Management Client has terminated\n");
        LOG(SCREEN, "**********************************************************\n");

        // Clear the FD for the connection socket.
        mgmtConnectionFD = 0;
        close(connectionFD);
        return;
    }

    // Decode the JSON request string
    jParsedJson = json_tokener_parse(buff);

    if (jParsedJson == NULL) {
        // JSON parse error. Print an error and bail.
        LOG(BOTH, "Sever received invalid JSON string from Mgmt Client\n");
        return;
    }

    // Extract the request type.
    json_object_object_get_ex(jParsedJson, "request", &jStringRequestType);

    // Handle the request
    if (printVerboseDebug) {
        LOG(BOTH, "Mgmt Client requested:- \"%s\"\n", json_object_get_string(jStringRequestType));
    }

    // Check what the Management Client requested,
    if (strcmp(json_object_get_string(jStringRequestType), "Current Connections") == 0) {
        // Request for Current Connection Information

        // File Logging - Report connection data request

        LOG(BOTH, "Received Mgmt Client Request:- Current Connections\n");
        LOG(SCREEN, "**********************************************************\n");

        json_object *jObject = json_object_new_object();
        json_object *jArray = json_object_new_array();

        // Start looking for an entries from the head of the list
        struct listEntry *pCurrent = pHead;

        while (pCurrent != NULL) {
            json_object *jLoopObject = json_object_new_object();

            json_object *jStringRemoteIPAddress = json_object_new_string(inet_ntoa(pCurrent->pPeerAddress->sin_addr));
            json_object *jIntRemoteIPPort = json_object_new_int(ntohs(pCurrent->pPeerAddress->sin_port));
            json_object *jStringTimeConnected = json_object_new_string(pCurrent->connectionStartTime);
            json_object *jIntProtocol = json_object_new_int(pCurrent->protocol);
            json_object *jStringRemoteTUNIPAddress = json_object_new_string(pCurrent->tunIP);

            json_object_object_add(jLoopObject, "remoteIP", jStringRemoteIPAddress);
            json_object_object_add(jLoopObject, "remotePort", jIntRemoteIPPort);
            json_object_object_add(jLoopObject, "timeOfConnection", jStringTimeConnected);
            json_object_object_add(jLoopObject, "protocol", jIntProtocol);
            json_object_object_add(jLoopObject, "remoteTunIP", jStringRemoteTUNIPAddress);

            // Add the object to the array
            json_object_array_add(jArray, jLoopObject);

            // Move to the next entry
            pCurrent = pCurrent->next;
        }

        // Add the array to the main JSON object
        json_object_object_add(jObject, "Connections", jArray);

        if (printVerboseDebug) {
            LOG(BOTH, "The JSON object created: %s\n", json_object_to_json_string(jObject));
        }

        strcpy(buff, json_object_to_json_string(jObject));

        // Send the data back to the manager
        len = SSL_write(pMgmtClientTLSSession->ssl, buff, strlen(buff));

        if ((len == 0) || (len == -1)) {
            // Error sending data
            LOG(LOGFILE, "Error sending data - TCP socket send\n");
            perror("TCP socket send");
        }

    } else if (strcmp(json_object_get_string(jStringRequestType), "Terminate Connection") == 0) {

        LOG(LOGFILE, "Received Mgmt Client Request:- Terminate Client\n");

        // Request to terminate connection. Determine which index
        int index;
        int pid;
        int sockFD;
        char *pTunIP = NULL;
        struct sockaddr_in *pPeerAddr = NULL;
        tlsSession *pTLSSession;

        json_object *jObject;
        json_object *jIntIndex;
        json_object *jStringResponseCode;

        json_object_object_get_ex(jParsedJson, "index", &jIntIndex);

        index = json_object_get_int(jIntIndex);

        pPeerAddr = getPidByIndex(index, &pid, &pTunIP, &sockFD, &pTLSSession);

        LOG(BOTH, "VPN Manager requested termination of connection for TUN IP %s. Peer address %s:%d\n",
            pTunIP,
            inet_ntoa(pPeerAddr->sin_addr),
            ntohs(pPeerAddr->sin_port));

        // Format the response message
        jObject = json_object_new_object();

        // Verify the PID we are about to kill
        if (pid != 0) {
            // A non zero PID means that we are trying to kill a TCP client child process.
            // Send a SIGTERM message to it
            if (kill(pid, SIGTERM) == 0) {
                // Process killed successfully
                jStringResponseCode = json_object_new_string("Success");
                LOG(BOTH, "Process killed successfully\n");

                // Delete the entry from the linked list
                deleteEntryByTunIP(pTunIP);
            } else {
                // Error in process termination
                jStringResponseCode = json_object_new_string("Failure");
                LOG(BOTH, "Error terminating process PID %d - TUN IP %s\n", pid, pTunIP);
            }
        } else {
            // Terminating a UDP connection. UDP is serviced by the parent process and the
            // UDP client will not 'notice' that the server is not responding due to the connectionless
            // nature of the transport.
            // Shutdown the DTLS SSL connection as the far end will see this as a connection close.
            int ret = SSL_shutdown(pTLSSession->ssl);

            if (ret == 0) {
                // SSL shutdown not yet finished. Must call a 2nd time
                SSL_shutdown(pTLSSession->ssl);

                // Process killed successfully
                LOG(BOTH, "Process terminated successfully.\n");
                jStringResponseCode = json_object_new_string("Success");

                // Delete the entry from the linked list
                deleteEntryByTunIP(pTunIP);
            } else if (ret < 0) {
                perror("sendto");

                // Error in process termination
                LOG(BOTH, "Error terminating UDP connection for TUN IP %s\n", pTunIP);
                jStringResponseCode = json_object_new_string("Failure");

            } else {
                // Process killed successfully
                LOG(BOTH, "Process terminated successfully.\n");
                jStringResponseCode = json_object_new_string("Success");

                // Delete the entry from the linked list
                deleteEntryByTunIP(pTunIP);
            }

            // Indicate no connected UDP client.
            udpClientConnected = false;
        }

        LOG(SCREEN, "**********************************************************\n");

        // Format up the response to the vpn manager
        json_object_object_add(jObject, "response", jStringResponseCode);

        // Copy the JSON string to 'buff'
        strcpy(buff, json_object_to_json_string(jObject));

        // Send the connection request to the server
        len = SSL_write(pMgmtClientTLSSession->ssl, buff, strlen(buff));

        if ((len == 0) || (len == -1)) {
            // Error sending data
            LOG(BOTH, "Error sending data - SSL send\n");
            perror("SSL send");
        }

    } else {
        LOG(BOTH, "Management Client received an unknown request - %s\n", buff);
    }
}

/*****************************************************************************************
 *
 * Function:            mgmtClientListenerSelected()
 *
 * Description:         Accept the management client connection and
 *                      fork a server process instance to deal with the
 *                      communication.
 *
 *****************************************************************************************/
void mgmtClientListenerSelected(int mgmtSockFD, SSL_CTX *tls_ctx) {
    ssize_t len;
    char buff[BUFF_SIZE];
    struct sockaddr_in *pPeerAddr;
    socklen_t addrSize = sizeof(struct sockaddr_in);
    int connectionFD;
    int pid;

    // Clear the buffer
    bzero(buff, BUFF_SIZE);

    // Allocate the memory for the peerAddr structure
    pPeerAddr = (struct sockaddr_in *) malloc(sizeof(struct sockaddr_in));

    // Verify the memory was allocated
    if (pPeerAddr == NULL) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    // Accept the new incoming connection
    connectionFD = accept(mgmtSockFD, (struct sockaddr *) pPeerAddr, &addrSize);

    if (connectionFD == -1) {
        perror("Error accepting TCP connection");
        return;
    }

    if (printVerboseDebug) {
        LOG(BOTH, "Connection FD for new management client connection is %d\n", connectionFD);
    }

    // Allocate the memory for a new TLS Session structure
    if ((pMgmtClientTLSSession = (tlsSession *) malloc(sizeof(tlsSession))) == NULL) {
        // Memory allocation failure
        perror("malloc");
        exit(EXIT_FAILURE);
    } else {
        // Clear the memory
        bzero(pMgmtClientTLSSession, sizeof(tlsSession));
    }

    // Create a new SSL object
    if ((pMgmtClientTLSSession->ssl = SSL_new(tls_ctx)) == NULL) {
        perror("Error creating Mgmt Client SSL structure.");
        free(pMgmtClientTLSSession);
        pMgmtClientTLSSession = NULL;
        return;
    }

    // Bind the ssl object with the socket
    SSL_set_fd(pMgmtClientTLSSession->ssl, connectionFD);

    // Perform the SSL Handshake
    if ((SSL_accept(pMgmtClientTLSSession->ssl)) == -1) {
        // Handshake error
        char msg[1024];
        ERR_error_string_n(ERR_get_error(), msg, sizeof(msg));
        printf("%s %s %s %s\n", msg, ERR_lib_error_string(0), ERR_func_error_string(0), ERR_reason_error_string(0));
        free(pMgmtClientTLSSession);
        pMgmtClientTLSSession = NULL;
        return;
    }

    len = SSL_read(pMgmtClientTLSSession->ssl, buff, BUFF_SIZE - 1);

    if (len == -1) {
        LOG(LOGFILE, "Mgmt Client Rcv error.\n");
        perror("TCP Rcv error");
        return;
    } else if (len == 0) {
        LOG(BOTH, "Management Client %s:%d has closed the connection\n",
            inet_ntoa(pPeerAddr->sin_addr),
            ntohs(pPeerAddr->sin_port));
        LOG(SCREEN, "**********************************************************\n");

        free(pMgmtClientTLSSession);
        pMgmtClientTLSSession = NULL;
        close(connectionFD);
        return;
    }

    // Check if its a new client connection
    if (strncmp("MGMT Connection Request", buff, 18) == 0) {
        // File Logging - Report Mgmt Client connection
        LOG(BOTH, "New Management client connection from %s:%d.\n",
            inet_ntoa(pPeerAddr->sin_addr),
            ntohs(pPeerAddr->sin_port));

    } else {
        // Error. We should only be receiving new connection requests on this socket FD.
        if (printVerboseDebug) {
            LOG(BOTH, "Error! - Data (not a connection request) received on Management Listener socket from %s:%d\n",
                inet_ntoa(pPeerAddr->sin_addr),
                ntohs(pPeerAddr->sin_port));
        } else {
            LOG(LOGFILE, "Error! - Data (not a connection request) received on Management Listener socket from %s:%d\n",
                inet_ntoa(pPeerAddr->sin_addr),
                ntohs(pPeerAddr->sin_port));
        }

        // Error in connection request. Close the SSL connection and free the structures.
        SSL_shutdown(pMgmtClientTLSSession->ssl);
        free(pMgmtClientTLSSession);
        pMgmtClientTLSSession = NULL;

        close(connectionFD);
        return;
    }
    LOG(SCREEN, "**********************************************************\n");

    mgmtConnectionFD = connectionFD;
}

/**********************************************************************************************************************
 *
 * Main Process program handling functions
 *
 **********************************************************************************************************************/

/*****************************************************************************************
 *
 * Function:            printUsage()
 *
 * Description:         Display the help for the command line option.
 *
 *****************************************************************************************/
void printUsage(int argc, char *argv[]) {
    fprintf(stdout, "\n Usage: %s [options]\n\n", argv[0]);
    fprintf(stdout, " Implements a VPN server using OpenSSL libraries. Supports both TCP and UDP transport\n"
                    " encrypted via TLS and DTLS respectively. Can support multiple simultaneous TCP connections\n"
                    " and one UDP based connection.\n\n");
    fprintf(stdout, " Optional Arguments:- \n");
    fprintf(stdout, "   -t --tcp-server-port\t\t: Local TCP Server Port. Default - 44444\n");
    fprintf(stdout, "   -u --udp-server-port\t\t: Local UDP Server Port. Default - 55555\n");
    fprintf(stdout, "   -v --verbose\t\t\t: Verbose debug logging.\n");
    fprintf(stdout, "   -i --ip-headers\t\t: Prints IP headers and message contents to stdout.\n");
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
    while ((opt = getopt_long(argc, argv, "t:u:ivh", long_options, NULL)) != -1) {
        switch (opt) {

            case 't':
                // Local TCP server port number.
                tcpPortNumber = (ushort) atoi(optarg);
                break;

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

    // Default the remote UDP port if it was not specified as an option.
    if (udpPortNumber == 0) {
        udpPortNumber = 55555;
    }

    // Default the remote TCP port if it was not specified as an option.
    if (tcpPortNumber == 0) {
        tcpPortNumber = 44444;
    }
}

/*****************************************************************************************
 *
 * Function:            sigChldHandler()
 *
 * Description:         SIGCHLD Handler for cleaning up the
 *                      terminated child processes.
 *
 *****************************************************************************************/
void sigChldHandler(int sig) {
    // TODO - File Logging - Do we need to report here? - Think its covered by the other places

    // Wait for the process to finish using the WNOHANG flag
    // to prevent the handler from blocking.
    while (waitpid((pid_t) (-1), 0, WNOHANG) > 0) {}
}

/*****************************************************************************************
 *
 * Function:            childParentPipeSelected()
 *
 * Description:         A child process has passed some data back
 *                      to the main parent server process through
 *                      the PIPE.
 *                      This indicates that the child is terminating.
 *                      The data passed back is the unique remote
 *                      TUN IP. This can be used to delete the child
 *                      entry from the linked list of current
 *                      connections
 *
 *****************************************************************************************/
void childParentPipeSelected() {

    ssize_t len;
    char buff[2000];

    // Read the data from the PIPE (TUN)
    len = read(childParentPipe[0], buff, BUFF_SIZE);

    if (len == 0) {
        perror("PIPE read error");
        exit(EXIT_FAILURE);
    }

    buff[len] = '\0';

    if (printVerboseDebug) {
        LOG(BOTH, "Parent received request to delete TUN IP %s from linked list!\n", buff);
    } else {
        LOG(LOGFILE, "Parent received request to delete TUN IP %s from linked list!\n", buff);
    }

    // Delete the child process entry from the linked list
    deleteEntryByTunIP(buff);

}

/*****************************************************************************************
 *
 * Function:            main()
 *
 * Description:         Main program loop.
 *                      Process the command line options, Create the TUN,
 *                      Create the UDP Server listener port and wait for
 *                      a connection.
 *
 *****************************************************************************************/
int main(int argc, char *argv[]) {

    struct sigaction sa;
    int tunFD, udpSockFD, tcpSockFD, mgmtSockFD, retVal, pid;
    pid_t c;
    char *v[3];

    // Process the user supplied command line options.
    processCmdLineOptions(argc, argv);

    if (geteuid() != 0) {
        printf("VPN server must be started with root privileges.\n");
        exit(EXIT_FAILURE);
    }

    // Open the log file for appending
    retVal = openlog();
    if (retVal == EXIT_FAILURE) {
        exit(EXIT_FAILURE);
    }

    LOG(BOTH, "**********************************************************\n");
    LOG(BOTH, "VPN Server Initialisation:\n");

    // Set the ip forwarding - sysctl net.ipv4.ip_forward=1
    LOG(BOTH, "Auto configuring IP forwarding\n");

    v[0] = "/sbin/sysctl";
    v[1] = "net.ipv4.ip_forward=1";
    v[2] = 0;

    // Need to fork off for the execve
    if ((pid = fork()) == 0) {
        // Child process
        retVal = execve(v[0], v, 0);
    } else {
        // Wait for the child to exit.
        c = wait(NULL);
    }

    if (retVal != 0) {
        LOG(BOTH, "Configuring IP forwarding returned Error code %d\n", retVal);
        exit(EXIT_FAILURE);
    }

    tunFD = createTunDevice();
    LOG(BOTH, "Configuring VPN TCP and UDP Listeners\n");
    tcpSockFD = initTCPServer(tcpPortNumber);
    udpSockFD = initUDPServer();

    // Create a socket for the Management Client connection.
    LOG(BOTH, "Configuring Management Client Listener\n");
    mgmtSockFD = initTCPServer(33333);

    // Register the SIGCHLD handler from reaping child TCP server processes
    sa.sa_handler = sigChldHandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;

    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("Server sigaction");
        exit(EXIT_FAILURE);
    }

    //create SSL contexts for both TCP and UDP protocols
    SSL_CTX *tls_ctx = NULL;
    SSL_CTX *dtls_ctx = NULL;

    //init both contexts using cert/key files
    tls_ctx = tls_ctx_init(TCP, SSL_VERIFY_PEER, CERT_FILE, KEY_FILE);
    if (tls_ctx == NULL) {
        perror("Server TCP tls_init");
        exit(EXIT_FAILURE);
    }

    dtls_ctx = tls_ctx_init(UDP, SSL_VERIFY_PEER, CERT_FILE, KEY_FILE);
    if (dtls_ctx == NULL) {
        perror("Server UDP tls_init");
        exit(EXIT_FAILURE);
    }

    // File logging - report initialisation complete
    LOG(BOTH, "VPN Server Initialisation Complete.\n");
    LOG(BOTH, "**********************************************************\n");

// Disable lint warning for endless loop.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-noreturn"
    // Enter the main server loop
    while (1) {
        fd_set readFDSet;

        FD_ZERO(&readFDSet);
        FD_SET(udpSockFD, &readFDSet);
        FD_SET(tcpSockFD, &readFDSet);
        FD_SET(mgmtSockFD, &readFDSet);
        FD_SET(childParentPipe[0], &readFDSet);

        // If a management client is connected. Add the socket to the list
        // the parent will service.
        if (mgmtConnectionFD != 0) {
            FD_SET(mgmtConnectionFD, &readFDSet);
        }

        FD_SET(tunFD, &readFDSet);

        if (select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL) == -1) {
            // select was interrupted. reset the loop.
            continue;
        }

        if (FD_ISSET(tunFD, &readFDSet)) tunSelected(tunFD);
        if (FD_ISSET(udpSockFD, &readFDSet)) udpSocketSelected(tunFD, udpSockFD, tcpSockFD, mgmtSockFD, dtls_ctx);
        if (FD_ISSET(tcpSockFD, &readFDSet))
            tcpListenerSocketSelected(tunFD, tcpSockFD, udpSockFD, mgmtSockFD, tls_ctx);
        if (FD_ISSET(mgmtSockFD, &readFDSet)) mgmtClientListenerSelected(mgmtSockFD, tls_ctx);
        if (FD_ISSET(childParentPipe[0], &readFDSet)) childParentPipeSelected();

        if (mgmtConnectionFD != 0) {
            if (FD_ISSET(mgmtConnectionFD, &readFDSet)) mgmtClientSocket(mgmtConnectionFD);
        }
    }

#pragma clang diagnostic pop
}
