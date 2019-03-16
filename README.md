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
    
To compile the code on a Raspberry Pi, we also need to install the openssl development libraries

    sudo apt-get install libssl-dev

The VPN Management Client requires authentication in order to terminate a session. The PAM development libraries are used for this purpose and need to be installed prior to building 

    sudo apt-get install libpam0g-dev
       
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
The client will default to use a UDP tunnel if no protocol is specified with the "--protocol" option.

    $ sudo ./vpnclient -s <serverIP> -n <Remote Network> -m <Remote Network Netmask> [--protocol tcp|udp]

--------------------------
To run the management client: 
--------------------------

The VPN manager should be run on the same host as vpn server.

    $ ./vpnmanager