#ifndef CANS_VPN_PROJECT_VPNMANAGER_H
#define CANS_VPN_PROJECT_VPNMANAGER_H
#include "tls.h"

int connectToTCPServer(tlsSession *pClientSession);
int displayMainMenu();
int displayCurrentConnections(int mgmtSockFD, tlsSession *pClientSession);
void terminateConnection(int mgmtSockFD, tlsSession *pClientSession);

#endif //CANS_VPN_PROJECT_VPNMANAGER_H
