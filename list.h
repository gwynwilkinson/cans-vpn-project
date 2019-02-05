#ifndef VPN_TEST_CODE_LIST_H
#define VPN_TEST_CODE_LIST_H
# include <stdbool.h>

struct listEntry {
    char tunIP[17];
    int protocol;
    struct sockaddr_in *pPeerAddress;
    int connectionFD;
    struct listEntry* next;
    struct listEntry* prev;
};

struct sockaddr_in* findIPAddress(char *pTunIP, int *pProtocol, int *pConnectionFD);
void insertTail(char *pTunIP, int protocol, struct sockaddr_in *pPeerAddr, int connectionFD);
bool updatePeerAddress(struct sockaddr_in *pNewPeerAddress, char pTunIP[]);

#endif //VPN_TEST_CODE_LIST_H
