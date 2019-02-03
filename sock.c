#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <stdio.h>
#include "sock.h"

/*********************************************************************
 *
 * Function:            sockCmpAddr)
 *
 * Description:         Compares two IPv4 address in a sockaddr_in
 *                      structure and returns "0" if they match.
 *
 *********************************************************************/
int sockCmpAddr(const struct sockaddr_in *pSa1, const struct sockaddr_in *pSa2) {

    char ip1[17];
    char ip2[17];

    // Basic sanity check that the two address structure families match.
    if (pSa1->sin_family != pSa2->sin_family) {
        printf("sockCmpAddr() - Address families incompatible\n");
        return (-1);

    }

    // Only perform the check for IPv4
    switch (pSa1->sin_family) {
        case AF_INET:

            // IP's are copied to a local structure as there seems to be a bug
            // when using inet_ntoa() twice with different address structures in
            // one line. When this happens, both addresses appear as the 2nd IP
            // and the compare breaks.
            strcpy(ip1, inet_ntoa(pSa1->sin_addr));
            strcpy(ip2, inet_ntoa(pSa2->sin_addr));

            printf("sockCmpAddr() - sa1 %s - sa2 %s\n", ip1, ip2);

            return(memcmp((void *) &(pSa1->sin_addr),
                              (void *) &(pSa2->sin_addr),
                              sizeof(struct in_addr)));

        default:
            return -1;
    }
}
