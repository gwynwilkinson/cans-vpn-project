#ifndef LOGGING_H
#define LOGGING_H

#define SCREEN 0
#define LOGFILE 1
#define BOTH 2

FILE *vpn_logfp;

/**************************************************************
 *
 * Function:            LOG()
 *
 * Description:         Logging to an open a logfile with timestamp. 
 *
 **************************************************************/
int LOG(int mode,char *fmt, ...);

/**************************************************************
 *
 * Function:            openlog()
 *
 * Description:         Logging function to open a logfile for appending. 
 *
 **************************************************************/
int openlog();

/**************************************************************
 *
 * Function:            closelog()
 *
 * Description:         Logging function to flush and close a logfile.
 *
 **************************************************************/
int closelog();

#endif // LOGGING_H
