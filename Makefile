CC=gcc
CFLAGS=-g
LDLIBS=-ljson-c -lssl -lcrypto -lpam -lpam_misc
DEPS = *h
SERVER_OBJ = list.o sock.o logging.o
COMMON_OBJ = debug.o tls.o logging.o
DESTDIR = /opt/vpn/bin/
CERTDIR = /opt/vpn/

%.o: %.c %(DEPS)
	$CC -c -o $@ $ $(LDLIBS)< $(CFLAGS)

all: vpnclient vpnserver vpnmanager

vpnclient: vpnclient.o $(COMMON_OBJ)
vpnserver: vpnserver.o $(COMMON_OBJ) $(SERVER_OBJ)
vpnmanager: vpnmanager.o $(COMMON_OBJ)

clean:
	rm vpnserver vpnclient vpnmanager *.o

install:
	mkdir -p $(DESTDIR)
	mkdir -p $(CERTDIR)
	cp vpnclient  $(DESTDIR)
	cp vpnserver  $(DESTDIR)
	cp vpnmanager $(DESTDIR)
    
	chmod 4755 $(DESTDIR)/vpnserver
	chmod 4755 $(DESTDIR)/vpnclient
	chmod 700 $(DESTDIR)/vpnmanager

	cp -r certs $(CERTDIR)
	chmod 700 $(CERTDIR)/certs
	chmod 600 $(CERTDIR)/certs/*.pem

uninstall:
	rm $(DESTDIR)/vpnserver
	rm $(DESTDIR)/vpnclient
	rm $(DESTDIR)/vpnmanager
	rm -rf $(CERTDIR)/certs
