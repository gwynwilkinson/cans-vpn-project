#include <stdlib.h>
#include <memory.h>
#include <arpa/inet.h>
#include <json-c/json.h>
#include <stdbool.h>
#include <stdio.h>
#include "vpnmanager.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "tls.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#define SERVER_PORT 33333
#define SERVER_IP "127.0.0.1"
#define EXIT_PROGRAM 99
#define BUFF_SIZE 2000
#define TCP 6
#define UDP 17

#define CERT_FILE "../certs/manager-cert.pem"
#define KEY_FILE  "../certs/manager-key.pem"

bool printVerboseDebug=false;

/**************************************************************
 *
 * Function:            main()
 *
 * Description:         Main program loop
 *
 **************************************************************/
int main(int argc, char *argv[]) {

    int menuOption = 0;
    int mgmtSockFD;

    // Connect to the Server.
    mgmtSockFD = connectToTCPServer();

    tlsSession client_session;

    if(tls_init(&client_session, false, TCP, SSL_VERIFY_NONE, SERVER_IP, CERT_FILE, KEY_FILE) == -1){
        perror("Client tls_init");
        exit(EXIT_FAILURE);
    }
    /*Bind the socket to the SSL structure*/
    SSL_set_fd(client_session.ssl,mgmtSockFD);

    /*Connect to the server, SSL layer.*/
    if(SSL_connect(client_session.ssl) != 1){
        perror("Client SSL_connect");
        exit(EXIT_FAILURE);
    }

    printf("SSL connection is successful\n");
    printf ("SSL connection using %s\n", SSL_get_cipher(client_session.ssl));


    // Main Menu loop
    while (menuOption != EXIT_PROGRAM) {

        // Display the menu
        menuOption = displayMainMenu();

        switch (menuOption) {
            case 1:
                displayCurrentConnections(mgmtSockFD);
                break;
            case 2:
                break;
            case 3:
                break;
            case 50:
                printVerboseDebug ^= 1;
                break;
            default:
                break;
        }
    }
}

/**************************************************************
 *
 * Function:            connectToTCPServer()
 *
 * Description:         Creates the TCP socket connection to the
 *                      remote VPN server on the management port
 *
 **************************************************************/
int connectToTCPServer() {

    struct sockaddr_in peerAddr;
    struct sockaddr_in localAddr;
    int mgmtSockFD;
    char *hello = "MGMT Connection Request";
    socklen_t saLen;
    ssize_t len;
    char buff[17];

    // Create the peer socket address (Internet) structure.
    memset(&peerAddr, 0, sizeof(peerAddr));
    peerAddr.sin_family = AF_INET;
    peerAddr.sin_port = htons(SERVER_PORT);
    peerAddr.sin_addr.s_addr = inet_addr(SERVER_IP);

    mgmtSockFD = socket(AF_INET, SOCK_STREAM, 0);

    if (mgmtSockFD == 0) {
        perror("TCP Socket Allocation");
        exit(EXIT_FAILURE);
    }

    // Obtain the local socket address information
    saLen = sizeof(localAddr);

    // Send a server connection request message to "connect" with the VPN server
    if (connect(mgmtSockFD, (struct sockaddr *) &peerAddr, sizeof(peerAddr)) == -1) {
        printf("\nServer is not running. Ensure server is running on the localhost before starting the manager\n\n");
        exit(EXIT_FAILURE);
    }

    // Get some info about the local socket
    if (getsockname(mgmtSockFD, (struct sockaddr *) &localAddr, &saLen) == -1) {
        perror("getsockname");
        exit(EXIT_FAILURE);
    }

    if(printVerboseDebug) {
        printf("Opened TCP socket. FD = %d. Bound to IP = %s:%d\n",
               mgmtSockFD,
               inet_ntoa(localAddr.sin_addr),
               (int) ntohs(localAddr.sin_port));
    }

    // Send the connection request to the server
    len = send(mgmtSockFD, hello, strlen(hello), 0);

    if (len == -1) {
        // Connection error
        perror("TCP Connection Error");
        exit(EXIT_FAILURE);
    } else if (len == 0) {
        printf("Connection Closed\n");
        exit(EXIT_FAILURE);
    }

    printf("Connected to server\n");

    return mgmtSockFD;

}

/**************************************************************
 *
 * Function:            displayMainMenu()
 *
 * Description:         Print the main menu and handle input
 *
 **************************************************************/
int displayMainMenu() {

    int menuOption;
    int status = 0;
    int temp;

    printf("\n VPN Management Main Menu\n");
    printf(" ========================\n\n");
    printf("  1 - Display current connections\n");
    printf("  2 - Terminate a connection\n");
    printf("  3 - ?????\n\n");
    printf(" 99 - Exit Program\n\n");
    printf(" Please enter an option between 1-3, or 99 to exit:- ");

    status = scanf("%d", &menuOption);

    // Handle any input error
    while ((status != 1) || ((menuOption < 1) || ((menuOption > 3) &&
                                                  ((menuOption != 99) && (menuOption != 50))))) {
        while ((temp = getchar()) != EOF && temp != '\n');
        printf("Invalid Input. Please enter an option between 1-3, 99 to exit:- ");
        status = scanf("%d", &menuOption);
    }

    fflush(stdin);

    return (menuOption);
}

/**************************************************************
 *
 * Function:            displayCurrentConnections()
 *
 * Description:         Print the main menu and handle input
 *
 **************************************************************/
void displayCurrentConnections(int mgmtSockFD) {


    char request[] = "Current Connections";
    char buff[BUFF_SIZE];
    json_object *jParsedJson;
    json_object *jConnections;
    json_object *jLoopObject;
    ssize_t len, numConnections;
    int i;

    // Send the connection request to the server
    len = send(mgmtSockFD, request, strlen(request), 0);

    if (len == -1) {
        // Connection error
        perror("TCP Connection Error");
        exit(EXIT_FAILURE);
    } else if (len == 0) {
        printf("Connection Closed\n");
        exit(EXIT_FAILURE);
    }

    // Wait for the server to respond with the JSON data
    len = recv(mgmtSockFD, buff, BUFF_SIZE, 0);

    if (len == -1) {
        // Connection error
        perror("MGMT Client TCP Connection Error");
        exit(EXIT_FAILURE);
    } else if(len == 0){
        printf("Server Terminted\n");
        exit(EXIT_SUCCESS);
    }

    buff[len] = '\0';

    printf("--------------------------------------------------------------------------------\n");

    printf("\n VPN Connection Status\n");
    printf(" =====================\n\n");

    if(printVerboseDebug) {
        printf("\nCurrent Connection response: %s\n\n", buff);
    }

    // Parse the JSON buffer
    jParsedJson = json_tokener_parse(buff);

    // Get the connections array
    json_object_object_get_ex(jParsedJson, "Connections", &jConnections);

    // Determine array length
    numConnections = json_object_array_length(jConnections);

    if(numConnections == 0) {
        printf(" No clients connected\n");
    }

    // Loop through the array
    for(i = 0; i < numConnections; i++) {
        json_object *jStringRemoteIPAddress;
        json_object *jIntRemoteIPPort;
        json_object *jStringTimeConnected;
        json_object *jIntProtocol;
        json_object *jStringRemoteTUNIPAddress;


        jLoopObject = json_object_array_get_idx(jConnections, i);

        json_object_object_get_ex(jLoopObject, "remoteIP", &jStringRemoteIPAddress);
        json_object_object_get_ex(jLoopObject, "remotePort", &jIntRemoteIPPort);
        json_object_object_get_ex(jLoopObject, "timeOfConnection", &jStringTimeConnected);
        json_object_object_get_ex(jLoopObject, "protocol", &jIntProtocol);
        json_object_object_get_ex(jLoopObject, "remoteTunIP", &jStringRemoteTUNIPAddress);

        printf(" Connection Index: %d\n", i);
        printf(" ====================\n");
        printf(" RemoteIPAddress:\t%s:%d\n", json_object_get_string(jStringRemoteIPAddress), json_object_get_int(jIntRemoteIPPort));
        printf(" TimeOfConnection:\t%s\n", json_object_get_string(jStringTimeConnected));
        printf(" Protocol:\t\t%s\n", (json_object_get_int(jIntProtocol) == UDP) ? "UDP" : "TCP");
        printf(" RemoteTunIP:\t\t%s\n\n", json_object_get_string(jStringRemoteTUNIPAddress));
    }

    printf("--------------------------------------------------------------------------------\n");

}
