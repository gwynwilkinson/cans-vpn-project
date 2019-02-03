#ifndef VPN_TEST_CODE_LIST_H
#define VPN_TEST_CODE_LIST_H
# include <stdbool.h>

struct listEntry {
    char tunIP[17];
    int protocol;
    struct sockaddr_in *pPeerAddress;
    struct listEntry* next;
    struct listEntry* prev;
};

struct sockaddr_in* findIPAddress(char *pTunIP, int protocol);
void insertTail(char *pTunIP, int protocol, struct sockaddr_in *peerAddr);
bool updatePeerAddress(struct sockaddr_in *pNewPeerAddress, char pTunIP[]);

#endif //VPN_TEST_CODE_LIST_H
