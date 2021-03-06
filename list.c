#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <time.h>
#include "list.h"
#include "vpnserver.h"
#include "sock.h"
#include "tls.h"

/*****************************************************************************************
 *
 * Function:            createListEntryStr()
 *
 * Description:         Create a new list entry structure and
 *                      return a pointer to it.
 *
 *****************************************************************************************/
struct listEntry* createListEntryStr(char *pTunIP, int protocol, struct sockaddr_in *pPeerAddr, int pipFD, int connectionFD, int pid, tlsSession *pTLSSession) {

    // Allocate the memory for the new list entry node.
    struct listEntry *pNewEntry  = (struct listEntry*)malloc(sizeof(struct listEntry));

    // Check the memory was allocated correctly
    if( pNewEntry == NULL) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    // Log the connection start time.
    getDateTime(pNewEntry->connectionStartTime);

    strcpy(pNewEntry->tunIP, pTunIP);
    pNewEntry->protocol = protocol;
    pNewEntry->pPeerAddress = pPeerAddr;
    pNewEntry->connectionFD = connectionFD;
    pNewEntry->pipeFD = pipFD;
    pNewEntry->pid = pid;
    pNewEntry->pTLSSession = pTLSSession;

    // Initialise the previous and next pointers
    pNewEntry->prev = NULL;
    pNewEntry->next = NULL;

    return pNewEntry;
}

/*****************************************************************************************
 *
 * Function:            insertAtTail()
 *
 * Description:         Insert a new list entry at the end of
 *                      the list..
 *
 *****************************************************************************************/
void insertTail(char *pTunIP, int protocol, struct sockaddr_in *pPeerAddr, int pipeFD, int connectionFD, int pid, tlsSession *pTLSSession) {

    // Start looking for an entry from the head of the list
    struct listEntry* pCurrent = pHead;

    // Create the new list entry node
    struct listEntry* pNewEntry = createListEntryStr(pTunIP, protocol, pPeerAddr, pipeFD, connectionFD, pid, pTLSSession);

    // Check to see if the head is empty. If so, insert there
    if(pHead == NULL ) {
        pHead = pNewEntry;
    } else {
        // Search the list to get to the last node
        while(pCurrent->next != NULL) {
            pCurrent = pCurrent->next;
        }

        // Got to the end of the list. Insert the new entry
        pCurrent->next = pNewEntry;
        pNewEntry->prev = pCurrent;
    }
}

/*****************************************************************************************
 *
 * Function:            deleteEntryByTUN()
 *
 * Description:         Find an entry in the list and delete it based on the supplied TUN IP
 *
 *****************************************************************************************/
void deleteEntryByTunIP(char* pTunIP) {

    // Start looking for an entry from the head of the list
    struct listEntry* pCurrent = pHead;
    struct listEntry* pPrevious = NULL;

    // Check for empty list
    if(pHead == NULL) {
        printf("deleteEntry() - Head == NULL\n");
        return;
    }

    // Find the correct entry to delete
    while(strcmp(pTunIP, pCurrent->tunIP) != 0) {
        // Check to see if this was the last node
        if(pCurrent->next == NULL) {
            printf("deleteEntry() Error!! - Could not find the list entry for TUN IP %s\n", pTunIP);
            return;

        } else {
            // Set previous to be the current link, and
            // set current to be the next node
            pPrevious = pCurrent;
            pCurrent = pCurrent->next;
        }
    }

    // Found the node, update the links
    if(pCurrent == pHead) {
        // Entry was at the head. Only need to update
        // the head variable.
        pHead = pHead->next;
    } else {
        // Set the previous node next entry to point to
        // the next element in the list
        pPrevious->next = pCurrent->next;

        // Set the next element's previous pointer to the
        // previous node if we are not the last node.
        if(pCurrent->next != NULL) {
            (pCurrent->next)->prev = pPrevious;
        }
    }

    // Free the TUN IP address allocation. Need to call strok()
    // 4 times to get the final part of the IP address.
    char delim[] = ".";
    char *ptr;
    ptr = strtok(pCurrent->tunIP, delim);
    ptr = strtok(NULL, delim);
    ptr = strtok(NULL, delim);
    ptr = strtok(NULL, delim);

    clientIPAddress[atoi(ptr)] = false;

    // Deallocate the memory
    free(pCurrent);

}

/*****************************************************************************************
 *
 * Function:            deleteEntryByPeerAddr()
 *
 * Description:         Find an entry in the list and delete it based on the supplied TUN IP
 *
 *****************************************************************************************/
void deleteEntryByPeerAddr(struct sockaddr_in *pPeerAddr) {

    // Start looking for an entry from the head of the list
    struct listEntry* pCurrent = pHead;
    struct listEntry* pPrevious = NULL;

    // Check for empty list
    if(pHead == NULL) {
        printf("deleteEntry() - Head == NULL\n");
        return;
    }

    // Find the correct entry to delete
    while(sockCmpAddr(pPeerAddr, pCurrent->pPeerAddress) != 0) {
        // Check to see if this was the last node
        if(pCurrent->next == NULL) {
            printf("deleteEntry() Error!! - Could not find the list entry for Peer IP %s:%d\n",
                   inet_ntoa(pPeerAddr->sin_addr),
                   (int) ntohs(pPeerAddr->sin_port));
            return;

        } else {
            // Set previous to be the current link, and
            // set current to be the next node
            pPrevious = pCurrent;
            pCurrent = pCurrent->next;
        }
    }

    // Found the node, update the links
    if(pCurrent == pHead) {
        // Entry was at the head. Only need to update
        // the head variable.
        pHead = pHead->next;
    } else {
        // Set the previous node next entry to point to
        // the next element in the list
        pPrevious->next = pCurrent->next;

        // Set the next element's previous pointer to the
        // previous node if we are not the last node.
        if(pCurrent->next != NULL) {
            (pCurrent->next)->prev = pPrevious;
        }
    }

    // Free the TUN IP address allocation. Need to call strok()
    // 4 times to get the final part of the IP address.
    char delim[] = ".";
    char *ptr;
    ptr = strtok(pCurrent->tunIP, delim);
    ptr = strtok(NULL, delim);
    ptr = strtok(NULL, delim);
    ptr = strtok(NULL, delim);

    clientIPAddress[atoi(ptr)] = false;

    // Deallocate the memory
    free(pCurrent);
}

/*****************************************************************************************
 *
 * Function:            findTUNIPAddress()
 *
 * Description:         Find an entry in the list based on the remote TUN IP
 *                      address in string format. EG ("10.4.0.1")
 *
 *****************************************************************************************/
struct sockaddr_in* findByTUNIPAddress(char *pTunIP, int *pProtocol, int *pPipeFD, int *pConnectionFD, tlsSession **ppTLSSession) {

    // Start looking for an entry from the head of the list
    struct listEntry* pCurrent = pHead;

    // Check for empty list
    if(pHead == NULL) {
        printf("findByTUNIPAddress() - Head == NULL\n");
        return NULL;
    }

    // Compare the TUN IPs
    while(strcmp(pTunIP, pCurrent->tunIP) != 0) {
        // Check to see if this was the last node
        if (pCurrent->next == NULL) {
            return NULL;
        } else {
            // Move to next node
            pCurrent = pCurrent->next;
        }
    }

    // Found the list entry for this IP. Set the protocol type
    *pProtocol = pCurrent->protocol;

    // Set the connection FD
    *pConnectionFD = pCurrent->connectionFD;

    // Set the PIPE FD
    *pPipeFD = pCurrent->pipeFD;

    *ppTLSSession = pCurrent->pTLSSession;

    return(pCurrent->pPeerAddress);
}

/*****************************************************************************************
 *
 * Function:            findPeerIPAddress()
 *
 * Description:         Find an entry in the list based on the Peer IP
 *                      address passed in a sockaddr_in structure.
 *
 *****************************************************************************************/
char *findByPeerIPAddress(struct sockaddr_in* pPeerAddr, tlsSession **ppClientSession) {

    // Start looking for an entry from the head of the list
    struct listEntry* pCurrent = pHead;

    // Check for empty list
    if(pHead == NULL) {
        return NULL;
    }

    while(sockCmpAddr(pPeerAddr, pCurrent->pPeerAddress) != 0) {
        // Check to see if this was the last node
        if (pCurrent->next == NULL) {
            return NULL;
        } else {
            // Move to next node
            pCurrent = pCurrent->next;
        }
    }

    *ppClientSession = pCurrent->pTLSSession;

    return(pCurrent->tunIP);
}

/*****************************************************************************************
 *
 * Function:            getPidByIndex()
 *
 * Description:         Obtain the child PID based on index position in the linked list.
 *                      (Used by the terminate connection index by management client).
 *                      Also returns the TUN IP, peer address structure and tunnel
 *                      connection FD.
 *
 *****************************************************************************************/
struct sockaddr_in* getPidByIndex(int index, int *pPid, char **ppTunIP, int *pSockFD,
        tlsSession **ppClientSession, int *pProtocol, int *pPipeFD) {

    int i = 0;

    // Start looking for an entry from the head of the list
    struct listEntry* pCurrent = pHead;

    while((pCurrent != NULL) && (i < index)) {
        pCurrent = pCurrent->next;
        i++;
    }

    if(pCurrent == NULL) {
        // Index appears to be invalid. Return.
        printf("getPidByIndex() Errror! - Could not find an entry for list index%d\n", index);
        return (0);
    } else {
        *pPid = pCurrent->pid;
        *pSockFD = pCurrent->connectionFD;
        *ppTunIP = pCurrent->tunIP;
        *ppClientSession = pCurrent->pTLSSession;
        *pProtocol = pCurrent->protocol;
        *pPipeFD = pCurrent->pipeFD;
        return(pCurrent->pPeerAddress);
    }

}

/*****************************************************************************************
 *
 * Function:            findUDPSession()
 *
 * Description:         Only one UDP client is supported at this time. Find the session associated
 *                      to it and return the DTLS information and Peer Address structures.
 *
 *****************************************************************************************/
tlsSession *findUDPSession(struct sockaddr_in **ppPeerAddr) {

    // Start looking for an entry from the head of the list
    struct listEntry* pCurrent = pHead;

    // Check for empty list
    if(pHead == NULL) {
        printf("findUDPSession() - Head == NULL\n");
        return NULL;
    }

    // Compare the TUN IPs
    while(pCurrent->protocol != UDP) {
        // Check to see if this was the last node
        if (pCurrent->next == NULL) {
            return NULL;
        } else {
            // Move to next node
            pCurrent = pCurrent->next;
        }
    }

    // Found the list entry for this IP. Return the TLS information
    *ppPeerAddr = pCurrent->pPeerAddress;
    return(pCurrent->pTLSSession);
}
/*****************************************************************************************
 *
 * Function:            getDateTime()
 *
 * Description:         Converts the current time into a string
 *                      of format "%d/%m/%Y - %H:%M:%S"
 *
 *****************************************************************************************/
void getDateTime(char pTimeString[]) {

    time_t current_time;
    struct tm *time_info;

    time(&current_time);
    time_info = localtime(&current_time);

    strftime(pTimeString, sizeof(char) * 22, "%d/%m/%Y - %H:%M:%S", time_info);
}
