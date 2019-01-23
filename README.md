*************************************************
* vpnserver.c vpn server program via UDP  
* vpnclient.c vpn client program via UDP 
************************************************

--------------------------
To compile the compile: 
--------------------------
$ make 


--------------------------
To run the server: 
--------------------------
$ sudo ./vpnserver


--------------------------
To run the client: 
--------------------------

First change the SERVER_IP in vpnclient.c to match with the server's ip.  
$ sudo ./vpnclient

TUN interfaces should be auto configured 

client - 10.4.2.99/24
server - 10.4.2.5/24
