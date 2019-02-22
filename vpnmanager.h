#ifndef CANS_VPN_PROJECT_VPNMANAGER_H
#define CANS_VPN_PROJECT_VPNMANAGER_H

int connectToTCPServer();

int displayMainMenu();

int displayCurrentConnections(int mgmtSockFD);
void terminateConnection(int mgmtSockFD);

#endif //CANS_VPN_PROJECT_VPNMANAGER_H
