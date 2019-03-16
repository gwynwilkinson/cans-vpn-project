#include <stdlib.h>
#include <memory.h>
#include <arpa/inet.h>
#include <json-c/json.h>
#include <stdbool.h>
#include <stdio.h>
#include <time.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "tls.h"
#include "logging.h"
#include "vpnmanager.h"
#include <security/pam_appl.h>
#include <security/pam_misc.h>

#define SERVER_PORT 33333
#define SERVER_IP "127.0.0.1"
#define EXIT_PROGRAM 99
#define BUFF_SIZE 2000
#define TCP 6
#define UDP 17

#define CERT_FILE "./certs/client-cert.pem"
#define KEY_FILE  "./certs/client-key.pem"

bool printVerboseDebug=false;

static struct pam_conv conv = {
        misc_conv,
        NULL
};

/*****************************************************************************************
 *
 * Function:            main()
 *
 * Description:         Main program loop
 *
 *****************************************************************************************/
int main(int argc, char *argv[]) {

    int menuOption = 0;
    int mgmtSockFD;
    tlsSession client_session;

    // Initialise the SSL context structures
    if(tls_init(&client_session, false, TCP, SSL_VERIFY_NONE, SERVER_IP, CERT_FILE, KEY_FILE) == -1){
        perror("Client tls_init");
        exit(EXIT_FAILURE);
    }

    // Connect to the Server.
    mgmtSockFD = connectToTCPServer(&client_session);

    // Main Menu loop
    while (menuOption != EXIT_PROGRAM) {

        // Display the menu
        menuOption = displayMainMenu();

        switch (menuOption) {
            case 1:
                displayCurrentConnections(mgmtSockFD, &client_session);
                break;
            case 2:
                terminateConnection(mgmtSockFD, &client_session);
                break;
            case 3:
                break;
            case 50:
                printVerboseDebug ^= 1;
                break;
            case 999:
                exit(EXIT_SUCCESS);
                break;
            default:
                break;
        }
    }
}

/*****************************************************************************************
 *
 * Function:            connectToTCPServer()
 *
 * Description:         Creates the TCP socket connection to the
 *                      remote VPN server on the management port
 *
 *****************************************************************************************/
int connectToTCPServer(tlsSession *pClientSession) {

    struct sockaddr_in peerAddr;
    struct sockaddr_in localAddr;
    int mgmtSockFD;
    char *hello = "MGMT Connection Request";
    socklen_t saLen;
    ssize_t len;
    char buff[17];
    int sslError;

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

    // Perform the TLS handshake
    printf("Perform Handshake\n");

    // Bind the socket to the SSL structure
    sslError = SSL_set_fd(pClientSession->ssl, mgmtSockFD);

    if (sslError != 1) {
        char msg[1024];
        ERR_error_string_n(ERR_get_error(), msg, sizeof(msg));
        printf("%s %s %s %s\n", msg, ERR_lib_error_string(0), ERR_func_error_string(0), ERR_reason_error_string(0));
        exit(EXIT_FAILURE);
    }

    // Connect to the server, SSL Layer
    if ((sslError = SSL_connect(pClientSession->ssl)) != 1) {
        char msg[1024];
        ERR_error_string_n(ERR_get_error(), msg, sizeof(msg));
        printf("%s %s %s %s\n", msg, ERR_lib_error_string(0), ERR_func_error_string(0), ERR_reason_error_string(0));
        exit(EXIT_FAILURE);
    }

    LOG(SCREEN, "SSL connection is successful\n");
    LOG(SCREEN, "SSL connection using %s\n", SSL_get_cipher(pClientSession->ssl));

    // Send the connection request to the server
    len = SSL_write(pClientSession->ssl, hello, strlen(hello));

    if (len == -1) {
        // Connection error
        perror("UDP Connection Error");
        exit(EXIT_FAILURE);
    }

    LOG(SCREEN, "Connected to server\n");
    printf("\n--------------------------------------------------------------------------------\n");

    return mgmtSockFD;

}

/*****************************************************************************************
 *
 * Function:            displayMainMenu()
 *
 * Description:         Print the main menu and handle input
 *
 *****************************************************************************************/
int displayMainMenu() {

    int menuOption;
    int status = 0;
    int temp;

    printf("\n VPN Management Main Menu\n");
    printf(" ========================\n\n");
    printf("   1 - Display current connections\n");
    printf("   2 - Terminate a connection\n");
    printf(" 999 - Exit Program\n\n");
    printf(" Please enter an option. 1, 2 or 999 to exit:- ");

    status = scanf("%d", &menuOption);

    // Handle any input error
    while ((status != 1) || ((menuOption < 1) || ((menuOption > 2) &&
                                                  ((menuOption != 999) && (menuOption != 50))))) {
        while ((temp = getchar()) != EOF && temp != '\n');
        printf("Invalid Input. Please enter an option. 1, 2 or 999 to exit:- ");
        status = scanf("%d", &menuOption);
    }

    fflush(stdin);

    return (menuOption);
}

/*****************************************************************************************
 *
 * Function:            displayCurrentConnections()
 *
 * Description:         Print the main menu and handle input
 *
 *****************************************************************************************/
int displayCurrentConnections(int mgmtSockFD, tlsSession *pClientSession) {

    char buff[BUFF_SIZE];
    json_object *jParsedJson;
    json_object *jConnections;
    json_object *jLoopObject;
    ssize_t len, numConnections;
    int i;
    struct tm tm;

    // Format up the request type of "Current Connections" in JSON format
    json_object *jObject = json_object_new_object();
    json_object *jStringRequestType = json_object_new_string("Current Connections");
    json_object_object_add(jObject, "request", jStringRequestType);

    // Copy the JSON string to 'buff'
    strcpy(buff, json_object_to_json_string(jObject));

    // Send the connection request to the server
    len = SSL_write(pClientSession->ssl, buff, strlen(buff));

    if (len == -1) {
        // Connection error
        char msg[1024];
        ERR_error_string_n(ERR_get_error(), msg, sizeof(msg));
        printf("%s %s %s %s\n", msg, ERR_lib_error_string(0), ERR_func_error_string(0), ERR_reason_error_string(0));
        exit(EXIT_FAILURE);
    } else if (len == 0) {
        printf("Connection Closed\n");
        exit(EXIT_FAILURE);
    }

    // Wait for the server to respond with the JSON data
    len = SSL_read(pClientSession->ssl, buff, BUFF_SIZE - 1);

    if (len == -1) {
        // Connection error
        char msg[1024];
        ERR_error_string_n(ERR_get_error(), msg, sizeof(msg));
        printf("%s %s %s %s\n", msg, ERR_lib_error_string(0), ERR_func_error_string(0), ERR_reason_error_string(0));
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

    if(jParsedJson == NULL) {
        // JSON parse error. Print an error and bail.
        printf("Sever returned invalid JSON string\n");
        return 0;
    }

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
        printf(" RemoteIPAddress:\t%s:%d\n", json_object_get_string(jStringRemoteIPAddress),
                json_object_get_int(jIntRemoteIPPort));
        printf(" TimeOfConnection:\t%s\n", json_object_get_string(jStringTimeConnected));

        // TODO - Could work out uptime here
        printf(" Protocol:\t\t%s\n", (json_object_get_int(jIntProtocol) == UDP) ? "UDP" : "TCP");
        printf(" RemoteTunIP:\t\t%s\n\n", json_object_get_string(jStringRemoteTUNIPAddress));
    }

    printf("--------------------------------------------------------------------------------\n");

    return((int)numConnections);
}

/*****************************************************************************************
 *
 * Function:            terminateConnection()
 *
 * Description:         Print the main menu and handle input
 *
 *****************************************************************************************/
void terminateConnection(int mgmtSockFD, tlsSession *pClientSession) {

    char buff[BUFF_SIZE];
    json_object *jParsedJson;
    json_object *jStringResponseCode;
    ssize_t len;
    int index, temp, numConnections;
    int status = 0;
    pam_handle_t *pamh=NULL;
    int retval;
    char user[50];

    getlogin_r(user, sizeof(user));

    printf("--------------------------------------------------------------------------------\n\n");
    printf("To terminate a session requires re-authentication. Please enter the password for user '%s'\n", user);

    // Start the PAM service
    retval = pam_start("check_user", user, &conv, &pamh);

    if (retval == PAM_SUCCESS)
        // Verify the user exists
        retval = pam_authenticate(pamh, 0);

    if (retval == PAM_SUCCESS)
        // Is the user allowed access?
        retval = pam_acct_mgmt(pamh, 0);

    // Close the PAM service
    if (pam_end(pamh,retval) != PAM_SUCCESS) {
        pamh = NULL;
        printf("check_user: failed to release authenticator\n");
        exit(1);
    }

    // Verify authentication status
    if (retval == PAM_SUCCESS) {
        printf("Authenticated\n");
    } else {
        printf("Not Authenticated\n");
        printf("--------------------------------------------------------------------------------\n");
        return;
    }

    // Display the current connections to the user
    numConnections = displayCurrentConnections(mgmtSockFD, pClientSession);

    // Check there is something to terminate
    if(numConnections == 0) {
        // Nothing connected. Return to the main menu
        return;
    }

    // Ask for input for which index we should terminate.
    printf("Please enter the connection index to terminate (Enter 999 to return):- ");

    status = scanf("%d", &index);

    // Handle any input error
    while ((status != 1) || ((index < 0) || ((index > numConnections - 1) &&
                                                  ((index != 999))))) {
        while ((temp = getchar()) != EOF && temp != '\n');
        printf("Invalid Input. Please enter a valid index or 999 to return:- ");
        status = scanf("%d", &index);
    }

    fflush(stdin);

    // Check if the user decided not to terminate a connection
    if(index == 999) {
        return;
    }

    // Format up the request type of "Terminate Connection" in JSON format with the
    json_object *jObject = json_object_new_object();
    json_object *jStringRequestType = json_object_new_string("Terminate Connection");
    json_object *jIntIndex = json_object_new_int(index);

    json_object_object_add(jObject, "request", jStringRequestType);
    json_object_object_add(jObject, "index", jIntIndex);

    // Copy the JSON string to 'buff'
    strcpy(buff, json_object_to_json_string(jObject));

    if(printVerboseDebug)
        LOG(SCREEN, "The JSON object created: %s\n", json_object_to_json_string(jObject));

    // Send the connection request to the server
    len = SSL_write(pClientSession->ssl, buff, strlen(buff));

    if (len == -1) {
        // Connection error
        char msg[1024];
        ERR_error_string_n(ERR_get_error(), msg, sizeof(msg));
        printf("%s %s %s %s\n", msg, ERR_lib_error_string(0), ERR_func_error_string(0), ERR_reason_error_string(0));
        exit(EXIT_FAILURE);
    } else if (len == 0) {
        printf("Connection Closed\n");
        exit(EXIT_FAILURE);
    }

    // Wait for the server to respond with the JSON data
    len = SSL_read(pClientSession->ssl, buff, BUFF_SIZE - 1);

    if (len == -1) {
        // Connection error
        char msg[1024];
        ERR_error_string_n(ERR_get_error(), msg, sizeof(msg));
        printf("%s %s %s %s\n", msg, ERR_lib_error_string(0), ERR_func_error_string(0), ERR_reason_error_string(0));
        exit(EXIT_FAILURE);
    } else if(len == 0){
        printf("Server Terminated\n");
        exit(EXIT_SUCCESS);
    }

    // Parse the JSON buffer
    jParsedJson = json_tokener_parse(buff);

    if(jParsedJson == NULL) {
        // JSON parse error. Print an error and bail.
        printf("Sever returned invalid JSON string\n");
        return;
    }

    // Get the connections array
    json_object_object_get_ex(jParsedJson, "response", &jStringResponseCode);

    if(strcmp(json_object_get_string(jStringResponseCode), "Success") == 0) {
        printf("Connection terminated\n");
    } else {
        printf("Error terminating connection\n");
    }

    printf("\n--------------------------------------------------------------------------------\n");

}
