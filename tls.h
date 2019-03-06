#ifndef VPN_TEST_CODE_TLS_H
#define VPN_TEST_CODE_TLS_H

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
} tlsSession;


int tls_init(tlsSession* session, bool isServer, int protocol, int verify, char *serverIP, char *certfile, char *keyfile);
SSL_CTX * tls_ctx_init( int protocol, int verify, char *certfile, char *keyfile);
int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len);
int verify_cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len);
int clientVerifyCallBack(int preverify_ok, X509_STORE_CTX *x509_ctx );

#endif //VPN_TEST_CODE_TLS_H
