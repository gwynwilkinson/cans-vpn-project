#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

typedef struct {
    SSL_CTX *ctx;
    SSL *ssl;
    BIO *bio;
} tls_session;

int tls_init(tls_session* session, bool isServer, int protocol, int verify, char *serverIP, char *certfile, char *keyfile);
SSL_CTX * tls_ctx_init( int protocol, int verify, char *certfile, char *keyfile);
