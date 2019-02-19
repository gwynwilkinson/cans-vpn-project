#ifndef CANS_VPN_PROJECT_VPNMANAGER_H
#define CANS_VPN_PROJECT_VPNMANAGER_H

int connectToTCPServer();

int displayMainMenu();

void displayCurrentConnections(int mgmtSockFD);

#endif //CANS_VPN_PROJECT_VPNMANAGER_H
