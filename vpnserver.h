#ifndef VPN_TEST_CODE_VPNSERVER_H
#define VPN_TEST_CODE_VPNSERVER_H
#include <stdbool.h>

extern struct listEntry* pHead;
extern bool printVerboseDebug;
extern bool clientIPAddress[];

#define ICMP 1
#define TCP 6
#define UDP 17

#endif //VPN_TEST_CODE_VPNSERVER_H
