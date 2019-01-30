CC=gcc
ccFlags=-g
DEPS = vpnserver.h vpnclient.h debug.h
COMMON_OBJ = debug.o

%.o: %.c %(DEPS)
	$CC -c -o $@ $ < $(CFLAGS)

all: vpnclient vpnserver

vpnclient: vpnclient.o $(COMMON_OBJ)
vpnserver: vpnserver.o $(COMMON_OBJ)

clean: 
	rm vpnserver vpnclient *.o
