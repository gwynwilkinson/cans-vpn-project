*************************************************
* vpnserver.c vpn server program via UDP or TCP  
* vpnclient.c vpn client program via UDP or TCP
************************************************

--------------------------
Clone the repository
--------------------------

    git clone https://gitlab.uwe.ac.uk/jd6-white/CANS-VPN-Project.git
    
--------------------------
Install the pre-requisites
--------------------------
The VPN Management Client and Server programs interchange data using a JSON formatted structure. As such, the libjson-c development libraries are required to be installed.

    sudo apt install libjson-c-dev
    
--------------------------
To compile the program: 
--------------------------
    $ make 

--------------------------
To run the server: 
--------------------------
    $ sudo ./vpnserver

--------------------------
To run the client: 
--------------------------

    $ sudo ./vpnclient

--------------------------
To run the management client: 
--------------------------

The VPN manager should be run on the same host as vpn server.

    $ ./vpnmanager