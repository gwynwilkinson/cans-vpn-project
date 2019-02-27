#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "tls.h"

#ifndef ICMP
#define ICMP 1
#endif

#ifndef TCP
#define TCP 6
#endif

#ifndef UDP
#define UDP 17
#endif

SSL_CTX *tls_ctx_init(int protocol, int verify, char *certfile, char *keyfile){

    SSL_library_init();
    SSL_load_error_strings();
    SSL_CTX *ctx;

    SSL_METHOD *method;
    if(protocol==TCP){
        method = (SSL_METHOD *)TLS_server_method();
    }else if (protocol==UDP){
        method = (SSL_METHOD *)DTLS_server_method();
    }else{
        printf("Error: Invalid protocol selected.\n");
        return NULL;
        // TODO - bring error handling and logging in line with elsewhere
    }

    ctx = SSL_CTX_new(method);
    if(ctx == NULL){
        printf("Error: Unable to create SSL context.\n");
        return NULL;
        // TODO - bring error handling and logging in line with elsewhere
    }

    // TODO - figure out what our cipher suite should be, currently haven't
    // been able to figure out from the docs what's best to use.
    // Use wireshark to see what's in the default handshake, it might be fine.
    // SSL_CTX_set_cipher_list( ? );

    SSL_CTX_set_verify(ctx, verify, NULL);

    int error = 0;

    error = SSL_CTX_use_certificate_file(ctx, certfile, SSL_FILETYPE_PEM);
    if (error != 1) {
        printf("Error: Unable to load certificate.\n");
        return NULL;
        // TODO - bring error handling and logging in line with elsewhere
    }


    error = SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM);
    if (error != 1) {
        printf("Error: Unable to load private key.\n");
        return NULL;
        // TODO - bring error handling and logging in line with elsewhere
    }


    error = SSL_CTX_check_private_key(ctx);
    if (error != 1) {
        printf("Error: Invalid Private Key.\n");
        return NULL;
        // TODO - bring error handling and logging in line with elsewhere
    }

    return ctx;
}


int tls_init(tls_session* session, bool isServer, int protocol, int verify, char *serverIP, char *certfile, char *keyfile){

    SSL_METHOD *method = NULL;

    SSL_library_init();
    SSL_load_error_strings();

    if(isServer && protocol==TCP){
        method = (SSL_METHOD *)TLS_server_method();
    }else if (isServer && protocol==UDP){
        method = (SSL_METHOD *)DTLS_server_method();
    }else if (!isServer && protocol==TCP){
        method = (SSL_METHOD *)TLS_client_method();
    }else if (!isServer && protocol==UDP){
        method = (SSL_METHOD *)DTLS_client_method();
    }else{
        printf("Error: Invalid protocol selected.\n");
        return -1;
        // TODO - bring error handling and logging in line with elsewhere
    }

    session->ctx = SSL_CTX_new(method);
    if(session->ctx == NULL){
        printf("Error: Unable to create SSL context.\n");
        return -1;
        // TODO - bring error handling and logging in line with elsewhere
    }

    // TODO - figure out what our cipher suite should be, currently haven't
    // been able to figure out from the docs what's best to use.
    // Use wireshark to see what's in the default handshake, it might be fine.
    // SSL_CTX_set_cipher_list( ? );

    SSL_CTX_set_verify(session->ctx, verify, NULL);

    int error = 0;

    error = SSL_CTX_use_certificate_file(session->ctx, certfile, SSL_FILETYPE_PEM);
    if (error != 1) {
        printf("Error: Unable to load certificate.\n");
        return -1;
        // TODO - bring error handling and logging in line with elsewhere
    }

    error = SSL_CTX_use_PrivateKey_file(session->ctx, keyfile, SSL_FILETYPE_PEM);
    if (error != 1) {
        printf("Error: Unable to load private key.\n");
        return -1;
        // TODO - bring error handling and logging in line with elsewhere
    }

    error = SSL_CTX_check_private_key(session->ctx);
    if (error != 1) {
        printf("Error: Invalid Private Key.\n");
        return -1;
        // TODO - bring error handling and logging in line with elsewhere
    }

    session->bio = BIO_new_ssl_connect(session->ctx);
    if (session->bio == NULL) {
        printf("Error: Unable to create BIO.\n");
        return -1;
        // TODO - bring error handling and logging in line with elsewhere
    }

    if(!isServer) BIO_set_conn_hostname(session->bio, serverIP);

    BIO_get_ssl(session->bio, &(session->ssl));
    if (session->ssl == NULL) {
        printf("Error: Unable to create SSL instance.\n");
        return -1;
        // TODO - bring error handling and logging in line with elsewhere
    }

    if(isServer){
        SSL_set_accept_state(session->ssl);
    }else{
        SSL_set_connect_state(session->ssl);
        SSL_set_mode(session->ssl, SSL_MODE_AUTO_RETRY);
    }
return 0;
}
