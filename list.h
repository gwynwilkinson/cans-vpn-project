#ifndef VPN_TEST_CODE_LIST_H
#define VPN_TEST_CODE_LIST_H
# include <stdbool.h>

struct listEntry {
    char tunIP[17];                         // String containing IP of remote TUN
    int protocol;                           // Protocol - UDP or TCP
    struct sockaddr_in *pPeerAddress;       // Peer address structure for UDP connection
    int pipeFD;                             // FD of PIPE for child process
    int connectionFD;                       // socketFD (TCP or UDP)
    struct listEntry* next;
    struct listEntry* prev;
};

struct sockaddr_in* findIPAddress(char *pTunIP, int *pProtocol, int *pPipeFD, int *pConnectionFD);
void insertTail(char *pTunIP, int protocol, struct sockaddr_in *pPeerAddr, int pipeFD, int connectionFD);
bool updatePeerAddress(struct sockaddr_in *pNewPeerAddress, char pTunIP[]);

#endif //VPN_TEST_CODE_LIST_H
