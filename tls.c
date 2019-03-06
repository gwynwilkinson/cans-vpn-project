#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <netdb.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "tls.h"
#include "vpnserver.h"

#define COOKIE_SECRET_LENGTH 16
unsigned char cookie_secret[COOKIE_SECRET_LENGTH];
int cookie_initialized=0;

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

    // TODO - WE NEED TO VERIFY THE SERVER CERT EXPIRY HERE??
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


int tls_init(tlsSession* session, bool isServer, int protocol, int verify, char *serverIP, char *certfile, char *keyfile){

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

    // TODO - !!!!MUST ADD HOST NAME CHECKING HERE!!!! (SEED Book 19.5.1 & 19.5.3)
    SSL_CTX_set_verify(session->ctx, verify, clientVerifyCallBack);

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

/*****************************************************************************************
 *
 * Function:            clientVerifyCallBack()
 *
 * Description:         On client connection, this callback is called to
 *                      verify the server certificate.
 *
 *****************************************************************************************/
int clientVerifyCallBack(int preverify_ok, X509_STORE_CTX *x509_ctx) {

    ASN1_TIME *certTime;
    char *pString;


    X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    int err = X509_STORE_CTX_get_error(x509_ctx);

    if(preverify_ok == 1) {
        printf("Server Certificate Verification passed.\n");

        ASN1_TIME *tm;
        BIO *b;
        tm = X509_getm_notAfter(cert);

        b = BIO_new_fp(stdout, BIO_NOCLOSE);

        printf("Server Certificate Expiry date:- ");
        ASN1_TIME_print(b, tm);
        printf("\n\n");

        int pDay=0, pSec=0;

        ASN1_TIME_diff(&pDay,  &pSec, NULL, tm);

        if(pDay <= 30) {
            printf("\n!!!! SERVER CERTIFICATE EXPIRES IN %d DAYS !!!!\n", pDay);
        }

        ASN1_STRING_free(tm);
        BIO_free(b);
    } else {
        // Dont report the self signed certificate error
        if(err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) {
            return 1;
        }

        printf("Verification failed: %s \n",
            X509_verify_cert_error_string(err));
    }
}


/*****************************************************************************************
 *
 * Function:            generate_cookie()
 *
 * Description:         Used by the DTLS handshake mechanism to help with prevention of
 *                      DoS by adding a cookie to the handshake.
 *
 *****************************************************************************************/
// TODO - Reference this properly. Cookie code taken from - https://github.com/nplab/DTLS-Examples/blob/master/src/dtls_udp_chargen.c
int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len)
{
    unsigned char *buffer, result[EVP_MAX_MD_SIZE];
    unsigned int length = 0, resultlength;
    union {
        struct sockaddr_storage ss;
        struct sockaddr_in6 s6;
        struct sockaddr_in s4;
    } peer;

    /* Initialize a random secret */
    if (!cookie_initialized)
    {
        if (!RAND_bytes(cookie_secret, COOKIE_SECRET_LENGTH))
        {
            printf("error setting random cookie secret\n");
            return 0;
        }
        cookie_initialized = 1;
    }

    /* Read peer information */
    (void) BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

    /* Create buffer with peer's address and port */
    length = 0;
    switch (peer.ss.ss_family) {
        case AF_INET:
            length += sizeof(struct in_addr);
            break;
        case AF_INET6:
            length += sizeof(struct in6_addr);
            break;
        default:
            OPENSSL_assert(0);
            break;
    }
    length += sizeof(in_port_t);
    buffer = (unsigned char*) OPENSSL_malloc(length);

    if (buffer == NULL)
    {
        printf("out of memory\n");
        return 0;
    }

    switch (peer.ss.ss_family) {
        case AF_INET:
            memcpy(buffer,
                   &peer.s4.sin_port,
                   sizeof(in_port_t));
            memcpy(buffer + sizeof(peer.s4.sin_port),
                   &peer.s4.sin_addr,
                   sizeof(struct in_addr));
            break;
        case AF_INET6:
            memcpy(buffer,
                   &peer.s6.sin6_port,
                   sizeof(in_port_t));
            memcpy(buffer + sizeof(in_port_t),
                   &peer.s6.sin6_addr,
                   sizeof(struct in6_addr));
            break;
        default:
            OPENSSL_assert(0);
            break;
    }

    /* Calculate HMAC of buffer using the secret */
    HMAC(EVP_sha1(), (const void*) cookie_secret, COOKIE_SECRET_LENGTH,
         (const unsigned char*) buffer, length, result, &resultlength);
    OPENSSL_free(buffer);

    memcpy(cookie, result, resultlength);
    *cookie_len = resultlength;

    return 1;
}

/*****************************************************************************************
 *
 * Function:            verify_cookie()
 *
 * Description:         Used by the DTLS handshake mechanism to help with prevention of
 *                      DoS by verifying the client returned the cookie we sent them in
 *                      the handshake.
 *
 *****************************************************************************************/
int verify_cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len)
{
    unsigned char *buffer, result[EVP_MAX_MD_SIZE];
    unsigned int length = 0, resultlength;
    union {
        struct sockaddr_storage ss;
        struct sockaddr_in6 s6;
        struct sockaddr_in s4;
    } peer;

    /* If secret isn't initialized yet, the cookie can't be valid */
    if (!cookie_initialized)
        return 0;

    /* Read peer information */
    (void) BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

    /* Create buffer with peer's address and port */
    length = 0;
    switch (peer.ss.ss_family) {
        case AF_INET:
            length += sizeof(struct in_addr);
            break;
        case AF_INET6:
            length += sizeof(struct in6_addr);
            break;
        default:
            OPENSSL_assert(0);
            break;
    }
    length += sizeof(in_port_t);
    buffer = (unsigned char*) OPENSSL_malloc(length);

    if (buffer == NULL)
    {
        printf("out of memory\n");
        return 0;
    }

    switch (peer.ss.ss_family) {
        case AF_INET:
            memcpy(buffer,
                   &peer.s4.sin_port,
                   sizeof(in_port_t));
            memcpy(buffer + sizeof(in_port_t),
                   &peer.s4.sin_addr,
                   sizeof(struct in_addr));
            break;
        case AF_INET6:
            memcpy(buffer,
                   &peer.s6.sin6_port,
                   sizeof(in_port_t));
            memcpy(buffer + sizeof(in_port_t),
                   &peer.s6.sin6_addr,
                   sizeof(struct in6_addr));
            break;
        default:
            OPENSSL_assert(0);
            break;
    }

    /* Calculate HMAC of buffer using the secret */
    HMAC(EVP_sha1(), (const void*) cookie_secret, COOKIE_SECRET_LENGTH,
         (const unsigned char*) buffer, length, result, &resultlength);
    OPENSSL_free(buffer);

    if (cookie_len == resultlength && memcmp(result, cookie, resultlength) == 0)
        return 1;

    return 0;
}
