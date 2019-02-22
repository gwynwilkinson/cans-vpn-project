#ifndef VPN_TEST_CODE_LIST_H
#define VPN_TEST_CODE_LIST_H
# include <stdbool.h>

struct listEntry {
    char tunIP[17];                         // String containing IP of remote TUN
    char connectionStartTime[22];           // String containing connection time in format "%d/%m/%Y - %H:%M:%S"
    int protocol;                           // Protocol - UDP or TCP
    struct sockaddr_in *pPeerAddress;       // Peer address structure for UDP connection
    int pipeFD;                             // FD of PIPE for child process
    int connectionFD;                       // socketFD (TCP or UDP)
    int pid;                                // Process ID of child process
    struct listEntry* next;
    struct listEntry* prev;
};

struct sockaddr_in* findByTUNIPAddress(char *pTunIP, int *pProtocol, int *pPipeFD, int *pConnectionFD);
char *findByPeerIPAddress(struct sockaddr_in* pPeerAddr);
void insertTail(char *pTunIP, int protocol, struct sockaddr_in *pPeerAddr, int pipeFD, int connectionFD, int pid);
bool updatePeerAddress(struct sockaddr_in *pNewPeerAddress, char pTunIP[]);
void deleteEntryByTunIP(char *pTunIP);
void deleteEntryByPeerAddr(struct sockaddr_in *pPeerAddr);
struct sockaddr_in* getPidByIndex(int index, int *pPid, char **ppTunIP, int *sockFD);
void getDateTime(char pTimeString[]);
#endif //VPN_TEST_CODE_LIST_H
