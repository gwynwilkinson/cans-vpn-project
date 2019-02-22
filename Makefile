CC=gcc
CFLAGS=-g
LDLIBS=-ljson-c -lssl -lcrypto
DEPS = *h
SERVER_OBJ = list.o sock.o
COMMON_OBJ = debug.o tls.o

%.o: %.c %(DEPS)
	$CC -c -o $@ $ $(LDLIBS)< $(CFLAGS)

all: vpnclient vpnserver vpnmanager

vpnclient: vpnclient.o $(COMMON_OBJ)
vpnserver: vpnserver.o $(COMMON_OBJ) $(SERVER_OBJ)
vpnmanager: vpnmanager.o

clean:
	rm vpnserver vpnclient *.o
