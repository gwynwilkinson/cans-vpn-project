#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include "list.h"
#include "vpnserver.h"
#include "sock.h"

/**************************************************************
 *
 * Function:            createListEntryStr()
 *
 * Description:         Create a new list entry structure and
 *                      return a pointer to it.
 *
 **************************************************************/
struct listEntry* createListEntryStr(char *pTunIP, int protocol, struct sockaddr_in *pPeerAddr) {

    // Allocate the memory for the new list entry node.
    struct listEntry *pNewEntry  = (struct listEntry*)malloc(sizeof(struct listEntry));

    // Check the memory was allocated correctly
    if( pNewEntry == NULL) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    strcpy(pNewEntry->tunIP, pTunIP);
    pNewEntry->protocol = protocol;
    pNewEntry->pPeerAddress = pPeerAddr;

    // Initialise the previous and next pointers
    pNewEntry->prev = NULL;
    pNewEntry->next = NULL;

    return pNewEntry;
}

/**************************************************************
 *
 * Function:            insertAtTail()
 *
 * Description:         Insert a new list entry at the end of
 *                      the list..
 *
 **************************************************************/
void insertTail(char *pTunIP, int protocol, struct sockaddr_in *pPeerAddr) {

    // Start looking for an entry from the head of the list
    struct listEntry* pCurrent = pHead;

    // Create the new list entry node
    struct listEntry* pNewEntry = createListEntryStr(pTunIP, protocol, pPeerAddr);

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

/**************************************************************
 *
 * Function:            deleteEntry()
 *
 * Description:         Find an entry in the list and delete it
 *
 **************************************************************/
void deleteEntry(int protocol, struct sockaddr_in *pPeerAddr) {

    // Start looking for an entry from the head of the list
    struct listEntry* pCurrent = pHead;
    struct listEntry* pPrevious = NULL;

    // Check for empty list
    if(pHead == NULL) {
        return;
    }

    // TODO - add protocol check too
    while(sockCmpAddr(pCurrent->pPeerAddress, pPeerAddr) != 0) {
        // Check to see if this was the last node
        if(pCurrent->next == NULL) {
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
        // previous node.
        (pCurrent->next)->prev = pPrevious;
    }
}

/**************************************************************
 *
 * Function:            findIPAddress()
 *
 * Description:         Find an entry in the list based on an IP
 *                      address in string format. EG ("10.4.0.1")
 *
 **************************************************************/
struct sockaddr_in* findIPAddress(char *pTunIP, int protocol) {

    // Start looking for an entry from the head of the list
    struct listEntry* pCurrent = pHead;

    // Check for empty list
    if(pHead == NULL) {
        printf("findIPAddress() - Head == NULL\n");
        return NULL;
    }

    while(strcmp(pTunIP, inet_ntoa(pCurrent->pPeerAddress->sin_addr)) != 0) {

        // Check to see if this was the last node
        if (pCurrent->next == NULL) {
            return NULL;
        } else {
            // Move to next node
            pCurrent = pCurrent->next;
        }
    }

    return(pCurrent->pPeerAddress);
}

/**************************************************************
 *
 * Function:            updatePeerAddress()
 *
 * Description:         Finds an existing entry in the linked list
 *                      and updates it with a new Peer Address
 *                      sockaddr_in structure.
 *
 *                      Returns 'true' if an entry was updated.
 *                      Returns 'false' if the entry was not found.
 *
 **************************************************************/
bool updatePeerAddress(struct sockaddr_in *pNewPeerAddress, char pTunIP[]) {

    // Start looking for an entry from the head of the list
    struct listEntry* pCurrent = pHead;

    // Check for empty list
    if(pHead == NULL) {
        return false;
    }

    while(sockCmpAddr(pNewPeerAddress, pCurrent->pPeerAddress) != 0) {
        // Check to see if this was the last node
        if (pCurrent->next == NULL) {
            return false;
        } else {
            // Move to next node
            pCurrent = pCurrent->next;
        }
    }

    // Free the memory for the old structure
    free(pCurrent->pPeerAddress);

    pCurrent->pPeerAddress = pNewPeerAddress;
    strcpy(pTunIP,pCurrent->tunIP);
    return true;
}