#include <stdio.h>
#include <time.h>
#include <error.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include "logging.h"


FILE *vpn_logfp = 0;

/**************************************************************
 *
 * Function:            LOG()
 *
 * Description:         Logging to an open a logfile with timestamp. 
 *
 **************************************************************/
int LOG(int mode, char *fmt, ...) {

    time_t t1;
    char array[100];
    va_list args;
    va_list argscopy;
    char *fmtcopy;
    time(&t1);

    // Get the current time.
    strftime(array, sizeof(array) - 1, "[%Y-%m-%d %H:%M:%S] ", localtime(&t1));

    if (mode == BOTH) {

        // Write the log to stdout.
        va_start(args, fmt);
        fputs(array, stdout);
        vprintf(fmt, args);
        va_end(args);

        // Write the log to the logfile. Only do this on the server
        // (if the FD for the log file is non zero)
        if (vpn_logfp != 0) {
            va_start(args, fmt);
            fputs(array, vpn_logfp);
            vfprintf(vpn_logfp, fmt, args);
            va_end(args);
        }
    } else if (mode == SCREEN) {
        fputs(array, stdout);

        // printf like normal
        va_start(args, fmt);
        vprintf(fmt, args);
        va_end(args);

    } else if (mode == LOGFILE) {
        // Write the log to the logfile. Only do this on the server
        // (if the FD for the log file is non zero)
        if (vpn_logfp != 0) {
            va_start(args, fmt);
            fputs(array, vpn_logfp);
            vfprintf(vpn_logfp, fmt, args);
            va_end(args);
        }
    }

    // Flush the file contents from the buffer to the disk
    fflush(vpn_logfp);

    return EXIT_SUCCESS;

}

/**************************************************************
 *
 * Function:            openlog()
 *
 * Description:         Logging function to open a logfile for appending. 
 *
 **************************************************************/
int openlog() {

    // Open a file on disk for writing

    if ((vpn_logfp = fopen(VPN_LOG, "a")) == NULL) {
        perror("Cannot open file: VPN_LOG");
        exit(EXIT_FAILURE);
    } else {
        LOG(LOGFILE, "Opened file: %s\n", VPN_LOG);

        return EXIT_SUCCESS;
    }
}

/**************************************************************
 *
 * Function:            closelog()
 *
 * Description:         Logging function to flush and close a logfile.
 *
 **************************************************************/
int closelog() {

    LOG(LOGFILE,"Closing file: %s\n", VPN_LOG);
    fflush(vpn_logfp);
    fclose(vpn_logfp);

    return EXIT_SUCCESS;
}

