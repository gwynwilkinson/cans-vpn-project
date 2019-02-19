#ifndef CANS_VPN_PROJECT_VPNMANAGER_H
#define CANS_VPN_PROJECT_VPNMANAGER_H

int connectToTCPServer();

int displayMainMenu();

void displayCurrentConnections(int mgmtSockFD);

void displayNcursesMainMenu();

void printInMiddle(WINDOW *win, int starty, int startx, int width, char *string, chtype color);

void func(char *name);
#endif //CANS_VPN_PROJECT_VPNMANAGER_H
