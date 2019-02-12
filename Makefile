CC=gcc
CFLAGS=-g
DEPS = *h
SERVER_OBJ = list.o sock.o
COMMON_OBJ = debug.o

%.o: %.c %(DEPS)
	$CC -c -o $@ $ < $(CFLAGS)

all: vpnclient vpnserver

vpnclient: vpnclient.o $(COMMON_OBJ)
vpnserver: vpnserver.o $(COMMON_OBJ) $(SERVER_OBJ)

clean: 
	rm vpnserver vpnclient *.o
