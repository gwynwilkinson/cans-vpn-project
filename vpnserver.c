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
#include "debug.h"
#include "list.h"
#include "logging.h"

#define BUFF_SIZE 2000
#define MAX_CLIENTS 250
#define PENDING_CONNECTIONS 5

#define ICMP 1
#define TCP 6
#define UDP 17

bool printVerboseDebug = false;
bool printIPHeaders = false;

static struct option long_options[] =
        {
                {"udp-server-port", required_argument, NULL, 'u'},
                {"tcp-server-port", required_argument, NULL, 't'},
                {"ip-headers",      no_argument,       NULL, 'i'},
                {"verbose",         no_argument,       NULL, 'v'},
                {"help",            no_argument,       NULL, 'h'},
                {NULL, 0,                              NULL, 0}
        };

ushort udpPortNumber = 0;
ushort tcpPortNumber = 0;

// Global variable for the IP lookup linked list.
struct listEntry *pHead = NULL;

// Array storing assigned client IP addresses in the range 10.4.0.x
bool clientIPAddress[MAX_CLIENTS] = {false};

int mgmtConnectionFD = 0;

// A PIPE used by the child to send data back to the Parent server process
// indicating that the child is terminating. This allows the parent server

int childParentPipe[2];

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

    // File logging - Report TUN creation

    LOG(LOGFILE,"TUN %s interface configuration completed successfully",ifr.ifr_name);

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

    //    printf("Created UDP socket. FD = %d. Bound to IP = %s:%d\n",
    //           udpSockFD,
    //           inet_ntoa(localAddr.sin_addr),
    //           (int) ntohs(localAddr.sin_port));

    // File Logging - Report UDP socket creation

    LOG(BOTH,"Created UDP socket. FD = %d. Bound to IP = %s:%d\n",
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

    // File Logging - Report TCP socket creation
    
    LOG(BOTH, "Created TCP socket. FD = %d. Bound to IP = %s:%d\n",
           tcpSockFD,
           inet_ntoa(localAddr.sin_addr),
           (int) ntohs(localAddr.sin_port));

    // Listen on the port
    if (listen(tcpSockFD, PENDING_CONNECTIONS) == -1) {
        perror("TCP Server listen");
        exit(EXIT_FAILURE);
    }



    return (tcpSockFD);
}

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
    int protocol;
    int connectionFD;
    int pipeFD;
    ssize_t len, size;

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
    pPeerAddr = findByTUNIPAddress(inet_ntoa(destAddr.sin_addr), &protocol, &pipeFD, &connectionFD);

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

    if (pPeerAddr == NULL) {
        fprintf(stderr, "!!!!ERROR!!!! - tunSelected() could not find peer address structure for dest IP %s\n\n",
                inet_ntoa(destAddr.sin_addr));
    }

    if (protocol == UDP) {
        // Send the message to the correct peer.
        size = sendto(connectionFD, buff, (size_t) len, 0, (struct sockaddr *) pPeerAddr,
                      sizeof(struct sockaddr));

    } else {
        // Connection FD for TCP is the PIPE FD.
        size = write(pipeFD, buff, (size_t) len);
    }

    if (size == 0) {
        perror("sendto");
    }
}


/*****************************************************************************************
 *
 * Function:            udpSocketSelected()
 *
 * Description:         Received a packet on the UDP socket (tunnel)
 *                      Send to the TUN device (application)
 *
 *****************************************************************************************/
void udpSocketSelected(int tunFD, int udpSockFD) {
    ssize_t len;
    char buff[BUFF_SIZE];
    struct sockaddr_in *pPeerAddr;
    struct iphdr *pIpHeader = (struct iphdr *) buff;
    socklen_t addrSize = sizeof(struct sockaddr_in);

    // Allocate the memory for the peerAddr structure
    pPeerAddr = (struct sockaddr_in *) malloc(sizeof(struct sockaddr_in));

    // Verify the memory was allocated
    if (pPeerAddr == NULL) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    bzero(buff, BUFF_SIZE);

    len = recvfrom(udpSockFD, buff, BUFF_SIZE, 0, (struct sockaddr *) pPeerAddr, &addrSize);

    // Check if its a new client connection
    if (strncmp("Connection Request", buff, 18) == 0) {

      // TODO - File Logging - Report new UDP Client Connection.
      LOG(BOTH, "New UDP client connection from %s:%d.\n",
                inet_ntoa(pPeerAddr->sin_addr),
                ntohs(pPeerAddr->sin_port));


        // Send back to the client a unique IP address.
        uniqueClientIPAddress(buff);

        // Ensure we got a client address
        if (buff[0] != '\0') {
            ssize_t size = sendto(udpSockFD, buff, strlen(buff), 0, (struct sockaddr *) pPeerAddr,
                                  sizeof(struct sockaddr));

            if (printVerboseDebug) {
	      LOG(BOTH, "Assigned IP %s to client\n", buff);
            }
	    else{
	      LOG(LOGFILE, "Assigned IP %s to client\n", buff);
	    }

            LOG(BOTH, "************************************************************\n");

            // Add the peer address structure to the linked list.
            // 0 is used for the PIPE FD as this is unused for UDP connections
            insertTail(buff, UDP, pPeerAddr, 0, udpSockFD, 0);
        }



        // Dont pass the new connection request to the TUN. Just return from the function.
        return;
    } else if (strncmp("Terminate UDP Connection", buff, 24) == 0) {

        // Client has requested to terminate the connection
        LOG(BOTH, "UDP client %s:%d terminating \n",
                inet_ntoa(pPeerAddr->sin_addr),
                ntohs(pPeerAddr->sin_port));

        // Delete the child process entry from the linked list
        deleteEntryByPeerAddr(pPeerAddr);

        // Entry cleaned up, return from the function.
        return;
    }

    // Ignore IPv6 packets
    if (pIpHeader->version == 6) {
        return;
    }

    if (printVerboseDebug) {
      LOG(BOTH,"UDP Tunnel->TUN - Source IP %s:%d - Length %d\n",
	  inet_ntoa(pPeerAddr->sin_addr),
	  (int) ntohs(pPeerAddr->sin_port),
	  (int) len);
    }
    else{
      LOG(LOGFILE,"UDP Tunnel->TUN - Source IP %s:%d - Length %d\n",
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
    struct sockaddr_in *pPeerAddr;
    ssize_t len, size;
    int connectionFD;
    int protocol = TCP;

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

    // Obtain the peerAddress structure for this destination and set
    // the protocol variable so that we can determine which method to
    // use.
    pPeerAddr = findByTUNIPAddress(inet_ntoa(destAddr.sin_addr), &protocol, &pipeFD, &connectionFD);

    // Send the buffer to the TCP socket
    size = send(connectionFD, buff, (size_t) len, 0);

    if (size == 0) {
        // Error sending data
        perror("TCP socket send");
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
void readChildTCPSocket(int tunFD, int connectionFD, struct sockaddr_in *pPeerAddr, int pipeFD) {
    char buff[BUFF_SIZE];
    struct iphdr *pIpHeader = (struct iphdr *) buff;
    ssize_t len;

    len = recv(connectionFD, buff, BUFF_SIZE - 1, 0);

    if (len == -1) {
        perror("Child server TCP recv");
        close(connectionFD);
        close(pipeFD);
        exit(EXIT_FAILURE);

    } else if (len == 0) {
        // Connection has been closed. Kill the connection and
        // child process
        // File Logging - Report TCP Client termination

      
      LOG(BOTH,"TCP Client %s:%d has closed the connection.\n",
	     inet_ntoa(pPeerAddr->sin_addr),
	     ntohs(pPeerAddr->sin_port));
      
      // Find the unique remote TUN IP address in the linked list structure
      // using the Peer IP and Port as a lookup.
      strcpy(buff, findByPeerIPAddress(pPeerAddr));
      
      write(childParentPipe[1], buff, sizeof(buff));
      
      if (printVerboseDebug) {
	LOG(BOTH,"Killing Child PID %d - Closing connection FD %d \n", (int) getpid(), connectionFD);
	LOG(BOTH,"CHILD - Sending remote TUN IP %s to parent\n",buff);
      }
      else{
	LOG(LOGFILE,"Killing Child PID %d - Closing connection FD %d \n", (int) getpid(), connectionFD);
	LOG(LOGFILE,"CHILD - Sending remote TUN IP %s to parent\n",buff);
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
        printf("TCP Tunnel->TUN - Source IP %s:%d - Length %d\n",
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
void vpnChildSubProcess(int udpSockFD, int tcpSockFD, int mgmtSockFD, struct sockaddr_in *pPeerAddr,
                        int pipeFD[], int connectionFD, int tunFD) {

    // This is the child instance of the server. Close down the TCP
    // server listener port, UDP port. We will only be concerned with
    // dealing with this TCP connection from now on.
    close(udpSockFD);
    close(tcpSockFD);
    close(mgmtSockFD);

    // Close the child write end of the pipe
    close(pipeFD[1]);

    if (printVerboseDebug) {
        printf("Spawned child server process PID-%d for connection FD:%d\n", getpid(), connectionFD);
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
        if (FD_ISSET(connectionFD, &readFDSet)) readChildTCPSocket(tunFD, connectionFD, pPeerAddr, pipeFD[0]);
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
void tcpListenerSocketSelected(int tunFD, int tcpSockFD, int udpSockFD, int mgmtSockFD) {
    ssize_t len;
    char buff[BUFF_SIZE];
    struct sockaddr_in *pPeerAddr;
    struct iphdr *pIpHeader = (struct iphdr *) buff;
    socklen_t addrSize = sizeof(struct sockaddr_in);
    int connectionFD;
    int pipeFD[2];
    int pid;

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
        printf("Connection FD for new connection is %d\n", connectionFD);
    }

    bzero(buff, BUFF_SIZE);
    len = recv(connectionFD, buff, BUFF_SIZE - 1, 0);

    if (len == -1) {
        // This shouldnt really happen. Close the connection FD anyway
        close(connectionFD);
        perror("TCP Rcv error");
        return;
    } else if (len == 0) {
        // This shouldnt really happen. Close the connection FD anyway
        close(connectionFD);
        return;
    }

    // Check if its a new client connection
    // File Logging - Report new TCP VPN connection
    if (strncmp("Connection Request", buff, 18) == 0) {
        LOG(BOTH, "New TCP client connection from %s:%d. Initialisation Msg:- %s\n",
                inet_ntoa(pPeerAddr->sin_addr),
                ntohs(pPeerAddr->sin_port), buff);

        // Determine and send back to the client a unique IP address.
        uniqueClientIPAddress(buff);

        // Ensure we got a client address
        if (buff[0] != '\0') {
            len = send(connectionFD, buff, strlen(buff), 0);

            if (len == -1) {
                perror("TCP Send error");
		LOG(LOGFILE,"TCP Send error.");
                return;
            }

            if (printVerboseDebug) {
	      LOG(BOTH,"Assigned IP %s to client\n", buff);
            }
	    else{
	      LOG(LOGFILE,"Assigned IP %s to client\n", buff);
	    }

            LOG(BOTH, "************************************************************\n");
        }



        // Create a PIPE for communication between parent/child
        pipe(pipeFD);

        if (printVerboseDebug) {
	  LOG(BOTH,"Created PIPE with FDs [%d] and [%d]\n", pipeFD[0], pipeFD[1]);
        }
	else{
	  LOG(LOGFILE,"Created PIPE with FDs [%d] and [%d]\n", pipeFD[0], pipeFD[1]);
	}
	


        // Fork a new server instance to deal with this TCP connection
        if ((pid = fork()) == 0) {
            // This is the Child process

            // Handle the child process sub-function
            vpnChildSubProcess(udpSockFD, tcpSockFD, mgmtSockFD, pPeerAddr, pipeFD, connectionFD, tunFD);

        } else {
            // This is the Parent process

            // Add the peer address structure to the linked list and store the pipeFD
            // so that the parent process can determine which child needs to handle
            // the TUN->tunnel communication. Also store the socket connectionFD
            // so that the child process can send the message to the correct connection
            insertTail(buff, TCP, pPeerAddr, pipeFD[1], connectionFD, pid);

            // Parent does not need the connection FD
            close(connectionFD);
            close(pipeFD[0]);
        }
    } else {
        // Error. We should only be receiving new connection requests on this socket FD.
        if (printVerboseDebug) {
	  LOG(BOTH,"Error! - Data (not a connection request) received on TCP Listener socket from %s:%d\n",
                   inet_ntoa(pPeerAddr->sin_addr),
                   ntohs(pPeerAddr->sin_port));
        }
	else{
	  LOG(LOGFILE,"Error! - Data (not a connection request) received on TCP Listener socket from %s:%d\n",
	      inet_ntoa(pPeerAddr->sin_addr),
	      ntohs(pPeerAddr->sin_port));
	}
	
        close(connectionFD);
    }
}


/*****************************************************************************************
 *
 * Function:            mgmtClientSocket()
 *
 * Description:         Subroutine to handle the main loop for the
 *                      Management client once it has connected.
 *
 *****************************************************************************************/
void mgmtClientSocket( int connectionFD) {

    json_object *jParsedJson;
    json_object *jStringRequestType;

    char buff[BUFF_SIZE];
    ssize_t len;

    bzero(buff, BUFF_SIZE);

    len = read(connectionFD, buff, BUFF_SIZE);

    if ((len == 0) || (len == -1)) {
        // Connection has been closed. Close the port and kill the process
        printf("Management Client has terminated\n");

        // Clear the FD for the connection socket.
        mgmtConnectionFD = 0;
        close(connectionFD);

        // TODO - File Logging - Report termination of mgmt client.

	LOG(LOGFILE,"Management Client has terminated\n");
        return;
    }

    // Decode the JSON request string
    jParsedJson = json_tokener_parse(buff);

    if(jParsedJson == NULL) {
        // JSON parse error. Print an error and bail.
      LOG(BOTH,"Sever received invalid JSON string from Mgmt Client\n");
        return;
    }

    // Extract the request type.
    json_object_object_get_ex(jParsedJson, "request", &jStringRequestType);

    // Handle the request
    if (printVerboseDebug) {
      LOG(BOTH,"Mgmt Client requested:- \"%s\"\n", json_object_get_string(jStringRequestType));
    }
    else{
      LOG(LOGFILE,"Mgmt Client requested:- \"%s\"\n", json_object_get_string(jStringRequestType));
    }
    

    // Check what the Management Client requested,
    if (strcmp(json_object_get_string(jStringRequestType), "Current Connections") == 0) {
        // Request for Current Connection Information

        // File Logging - Report connection data request
      
      LOG(LOGFILE,"Received connection data request\n",jStringRequestType);

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

        if(printVerboseDebug) {
	  LOG(BOTH,"The JSON object created: %s\n", json_object_to_json_string(jObject));
        }
	else{
	  LOG(LOGFILE,"The JSON object created: %s\n", json_object_to_json_string(jObject));
	}

        strcpy(buff, json_object_to_json_string(jObject));

        // Send the data back to the manager
        len = send(connectionFD, buff, sizeof(buff), 0);

        if ((len == 0) || (len == -1)) {
            // Error sending data
	  LOG(LOGFILE,"Error sending data - TCP socket send\n");
            perror("TCP socket send");
        }

    } else if (strcmp(json_object_get_string(jStringRequestType), "Terminate Connection") == 0) {

        // TODO - Log termination of a client

      LOG(LOGFILE,"Received Terminate Connection Request: %s\n",jStringRequestType);
      

        // Request to terminate connection. Determine which index
        int index;
        int pid;
        int sockFD;
        char *pTunIP = NULL;
        struct sockaddr_in *pPeerAddr = NULL;

        json_object *jObject;
        json_object *jIntIndex;
        json_object *jStringResponseCode;

        json_object_object_get_ex(jParsedJson, "index", &jIntIndex);

        index = json_object_get_int(jIntIndex);

        pPeerAddr = getPidByIndex(index, &pid, &pTunIP, &sockFD);

        LOG(BOTH,"VPN Manager requested termination of connection for TUN IP %s. Peer address %s:%d\n",
               pTunIP,
               inet_ntoa(pPeerAddr->sin_addr),
               ntohs(pPeerAddr->sin_port));

        // Format the response message
        jObject = json_object_new_object();

        if(pid != 0) {
            if(kill(pid, SIGTERM) == 0) {
                // Process killed successfully
                jStringResponseCode = json_object_new_string("Success");
		LOG(LOGFILE,"Process killed successfully\n");

                // Delete the entry from the linked list
                deleteEntryByTunIP(pTunIP);
		LOG(LOGFILE,"Entry for tunIP: %\n",pTunIP);

            } else {
                // Error in process termination
                jStringResponseCode = json_object_new_string("Failure");
		LOG(LOGFILE,"Error terminating process\n");

            }

        } else {

            // Terminating a UDP connection. UDP is serviced by the parent process and the
            // UDP client will not 'notice' that the server is not responding due to the connectionless
            // nature of the transport.
            // Send back a message to the client indicating that we are terminating the connection, and then
            // remove the list entry for this connection.

            char terminateBuffer[21] = "Terminate Connection";

            // Send the message to the correct peer.
            len = sendto(sockFD, terminateBuffer, sizeof(terminateBuffer), 0, (struct sockaddr *) pPeerAddr,
                          sizeof(struct sockaddr));

            if ((len == 0) || (len == -1)) {
                perror("sendto");

                // Error in process termination
		LOG(LOGFILE,"Error in process termination.\n");
                jStringResponseCode = json_object_new_string("Failure");

            } else {
                // Process killed successfully
	      LOG(LOGFILE,"Process terminated successfully.\n");
                jStringResponseCode = json_object_new_string("Success");

                // Delete the entry from the linked list
		LOG(LOGFILE,"Entry %s deleted from list\n",pTunIP);
                deleteEntryByTunIP(pTunIP);
            }

        }

        // Format up the response to the vpn manager
        json_object_object_add(jObject, "response", jStringResponseCode);

        // Copy the JSON string to 'buff'
        strcpy(buff, json_object_to_json_string(jObject));

        // Send the connection request to the server
        len = send(connectionFD, buff, strlen(buff), 0);

        if ((len == 0) || (len == -1)) {
            // Error sending data
	  LOG(LOGFILE,"Error sending data - TCP socket send\n");
            perror("TCP socket send");
        }


    } else {
        LOG(BOTH,"UNKNOWN REQUEST %s\n", buff);
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
void mgmtClientListenerSelected(int mgmtSockFD) {
    ssize_t len;
    char buff[BUFF_SIZE];
    struct sockaddr_in *pPeerAddr;
    socklen_t addrSize = sizeof(struct sockaddr_in);
    int connectionFD;
    int pid;

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
      LOG(BOTH,"Connection FD for new management client connection is %d\n", connectionFD);
    }
    else{
      LOG(LOGFILE,"Connection FD for new management client connection is %d\n", connectionFD);
    }

    bzero(buff, BUFF_SIZE);
    len = recv(connectionFD, buff, BUFF_SIZE - 1, 0);

    if (len == -1) {
      LOG(LOGFILE,"TCP Rcv error.\n");
        perror("TCP Rcv error");
        return;
    } else if (len == 0) {
      
      LOG(BOTH,"Management Client %s:%d has closed the connection\n",
	  inet_ntoa(pPeerAddr->sin_addr),
	  ntohs(pPeerAddr->sin_port));
      
      close(connectionFD);
      return;
    }

    // Check if its a new client connection
    if (strncmp("MGMT Connection Request", buff, 18) == 0) {
      // TODO - File Logging - Report Mgmt Client connection
      LOG(BOTH, "New Management client connection from %s:%d. Initialisation Msg:- %s\n",
	      inet_ntoa(pPeerAddr->sin_addr),
	      ntohs(pPeerAddr->sin_port), buff);
      

    } else {
        // Error. We should only be receiving new connection requests on this socket FD.
        if (printVerboseDebug) {
	  LOG(BOTH,"Error! - Data (not a connection request) received on Management Listener socket from %s:%d\n",
	      inet_ntoa(pPeerAddr->sin_addr),
	      ntohs(pPeerAddr->sin_port));
        }
	else{
	  LOG(LOGFILE,"Error! - Data (not a connection request) received on Management Listener socket from %s:%d\n",
	      inet_ntoa(pPeerAddr->sin_addr),
	      ntohs(pPeerAddr->sin_port));
	}

        close(connectionFD);
    }

    mgmtConnectionFD = connectionFD;
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
    fprintf(stdout, " Proof of concept for VPN Server\n\n");
    fprintf(stdout, " Mandatory Arguments:- \n");
    fprintf(stdout, "   \n");
    fprintf(stdout, "\n Optional Arguments:- \n");
    fprintf(stdout, "   -t --tcp-server-port\t\t: Local TCP Server Port. Default - 44444\n");
    fprintf(stdout, "   -u --udp-server-port\t\t: Local UDP Server Port. Default - 55555\n");
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
void childParentPipeSelected(){

    ssize_t len;
    char buff[2000];

    // Read the data from the PIPE (TUN)
    len = read(childParentPipe[0], buff, BUFF_SIZE);

    if (len == 0) {
        perror("PIPE read error");
        exit(EXIT_FAILURE);
    }

    buff[len] = '\0';

    if(printVerboseDebug) {
      LOG(BOTH,"Parent received request to delete TUN IP %s from linked list!\n", buff);
    }
    else{
      LOG(LOGFILE,"Parent received request to delete TUN IP %s from linked list!\n", buff);
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
    int tunFD, udpSockFD, tcpSockFD, mgmtSockFD, retVal;

    // Process the user supplied command line options.
    processCmdLineOptions(argc, argv);

    openlog();
    

    LOG(BOTH,"************************************************************\n");
    LOG(BOTH,"VPN Server Initialisation:\n");

    // Set the ip forwarding - sysctl net.ipv4.ip_forward=1
    LOG(BOTH,"Auto configuring IP forwarding\n ");
    retVal = system("/sbin/sysctl net.ipv4.ip_forward=1");

    if (retVal != 0) {
      LOG(BOTH,"Configuring IP forwarding returned Error code %d\n", retVal);
        exit(EXIT_FAILURE);
    }

    tunFD = createTunDevice();
    LOG(BOTH,"Configuring VPN TCP Listener\n");
    tcpSockFD = initTCPServer(tcpPortNumber);
    udpSockFD = initUDPServer();

    // Create a socket for the Management Client connection.
    LOG(BOTH,"Configuring Management Client Listener\n");
    mgmtSockFD = initTCPServer(33333);

    // Register the SIGCHLD handler from reaping child TCP server processes
    sa.sa_handler = sigChldHandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;

    if(sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("Server sigaction");
        exit(EXIT_FAILURE);
    }

    // TODO - File logging - report initialisation complete
    LOG(BOTH,"VPN Server Initialisation Complete.\n");
    LOG(BOTH,"************************************************************\n");

    pipe(childParentPipe);

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
        if(mgmtConnectionFD != 0) {
            FD_SET(mgmtConnectionFD, &readFDSet);
        }

        FD_SET(tunFD, &readFDSet);

        if (select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL) == -1 ) {
            // select was interrupted. reset the loop.
            continue;
        }

        if (FD_ISSET(tunFD, &readFDSet)) tunSelected(tunFD);
        if (FD_ISSET(udpSockFD, &readFDSet)) udpSocketSelected(tunFD, udpSockFD);
        if (FD_ISSET(tcpSockFD, &readFDSet)) tcpListenerSocketSelected(tunFD, tcpSockFD, udpSockFD, mgmtSockFD);
        if (FD_ISSET(mgmtSockFD, &readFDSet)) mgmtClientListenerSelected(mgmtSockFD);
        if (FD_ISSET(childParentPipe[0], &readFDSet)) childParentPipeSelected();

        if(mgmtConnectionFD != 0) {
            if (FD_ISSET(mgmtConnectionFD, &readFDSet)) mgmtClientSocket(mgmtConnectionFD);
        }
    }
}

