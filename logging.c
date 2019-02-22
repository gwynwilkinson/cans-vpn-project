#include <stdio.h>
#include <time.h>
#include <error.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>

#define VPN_LOG "/var/log/vpn.log"


#define SCREEN 0
#define LOGFILE 1
#define BOTH 2

static FILE *vpn_logfp;

/**************************************************************
 *
 * Function:            LOG()
 *
 * Description:         Logging to an open a logfile with timestamp. 
 *
 *                      
 *
 **************************************************************/

int LOG(int mode,char *fmt, ...){

time_t t1;

char array[100];

 va_list args;
 va_list argscopy;
 char *fmtcopy;
 
 time(&t1);
 
 strftime(array, sizeof(array) -1, "[%Y-%m-%d %H:%M:%S] ", localtime(&t1));

 if(mode == BOTH){
   
   /* printf like normal */
   va_start(args, fmt);
   fputs(array, stdout);
   vprintf(fmt, args);
   va_end(args);
   
   va_start(args, fmt);
   fputs(array, vpn_logfp);
   vfprintf(vpn_logfp,fmt, args);
   va_end(args);
   
 }
 else if(mode == SCREEN){
   fputs(array, stdout);
   
   /* printf like normal */
   va_start(args, fmt);
   vprintf(fmt, args);
   va_end(args);
   
 }
 else if(mode == LOGFILE){
   va_start(args, fmt);
   fputs(array, vpn_logfp);
   vfprintf(vpn_logfp,fmt, args);
   va_end(args);
 }

 return EXIT_SUCCESS;
 
}

/**************************************************************
 *
 * Function:            openlog()
 *
 * Description:         Logging function to open a logfile for appending. 
 *
 *                      
 *
 **************************************************************/


int openlog(){

/* 
** Open a file on disk for writing
*/

  if((vpn_logfp = fopen(VPN_LOG, "a")) == NULL){
    perror("Cannot open file: VPN_LOG");
    return EXIT_FAILURE;
  }
  else{
    LOG(LOGFILE,"Opened file: %s\n",VPN_LOG);
    return EXIT_SUCCESS;
  }
}

/**************************************************************
 *
 * Function:            closelog()
 *
 * Description:         Logging function to flush and close a logfile.
 *
 *                      
 *
 **************************************************************/
int closelog(){

  fflush(vpn_logfp);
  fclose(vpn_logfp);
  
  return EXIT_SUCCESS;
}

