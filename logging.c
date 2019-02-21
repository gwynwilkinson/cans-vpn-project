#include <stdio.h>
#include <time.h>
#include <error.h>

#define VPN_LOG "/var/log/vpn.log"

static FILE *vpn_logfp;


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
    return 0;
  }
  else{
    //    printf("Opened file: %s\n",VPN_LOG);
    return 1;
  }
  
}

/**************************************************************
 *
 * Function:            LOG()
 *
 * Description:         Logging to an open a logfile with timestamp. 
 *
 *                      
 *
 **************************************************************/
int LOG(char *logline){

time_t t1;

char array[100];

time(&t1);

 strftime(array, sizeof(array) -1, "[%Y-%m-%d %H:%M:%S]", localtime(&t1));

 fprintf(vpn_logfp, "%s %s\n", array, logline);

 return 1;
 
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
  
}

