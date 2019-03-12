#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
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

// Support both Elliptic Curve and RSA certificates.
const char* const CHOSEN_CIPHERS = "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:";

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

    // Define which cipher(s) we want TLS to use
    SSL_CTX_set_cipher_list(ctx, CHOSEN_CIPHERS );

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

    SSL_CTX_set_cipher_list(session->ctx, CHOSEN_CIPHERS );

    SSL_CTX_set_verify(session->ctx, verify, clientVerifyCallBack);

    SSL_CTX_load_verify_locations(session->ctx, NULL, "./certs");


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

    // TODO - do not hardcode the hostname once we have our Pis set up
    X509_VERIFY_PARAM *vpm = SSL_get0_param(session->ssl);
    X509_VERIFY_PARAM_set1_host(vpm, "vpn-server", 0);

    SSL_set_connect_state(session->ssl);
    SSL_set_mode(session->ssl, SSL_MODE_AUTO_RETRY);

return 0;
}

/*****************************************************************************************
 *
 * Function:            print_cn_name()
 *
 * Description:         Prints certificate Common Name - code taken from OpenSSL Wiki
 *                      (Delete if unused)
 *
 *****************************************************************************************/
void print_cn_name(const char* label, X509_NAME* const name)
{
    int idx = -1, success = 0;
    unsigned char *utf8 = NULL;

    do
    {
        if(!name) break; /* failed */

        idx = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
        if(!(idx > -1))  break; /* failed */

        X509_NAME_ENTRY* entry = X509_NAME_get_entry(name, idx);
        if(!entry) break; /* failed */

        ASN1_STRING* data = X509_NAME_ENTRY_get_data(entry);
        if(!data) break; /* failed */

        int length = ASN1_STRING_to_UTF8(&utf8, data);
        if(!utf8 || !(length > 0))  break; /* failed */

        fprintf(stdout, "  %s: %s\n", label, utf8);
        success = 1;

    } while (0);

    if(utf8)
        OPENSSL_free(utf8);

    if(!success)
        fprintf(stdout, "  %s: <not available>\n", label);
}

/*****************************************************************************************
 *
 * Function:            print_san_name()
 *
 * Description:         Prints certificate Subject Alternate Name - code taken from OpenSSL Wiki
 *                      (Delete if unused)
 *
 *****************************************************************************************/
void print_san_name(const char* label, X509* const cert)
{
    int success = 0;
    GENERAL_NAMES* names = NULL;
    unsigned char* utf8 = NULL;

    do
    {
        if(!cert) break; /* failed */

        names = X509_get_ext_d2i(cert, NID_subject_alt_name, 0, 0 );
        if(!names) break;

        int i = 0, count = sk_GENERAL_NAME_num(names);
        if(!count) break; /* failed */

        for( i = 0; i < count; ++i )
        {
            GENERAL_NAME* entry = sk_GENERAL_NAME_value(names, i);
            if(!entry) continue;

            if(GEN_DNS == entry->type)
            {
                int len1 = 0, len2 = -1;

                len1 = ASN1_STRING_to_UTF8(&utf8, entry->d.dNSName);
                if(utf8) {
                    len2 = (int)strlen((const char*)utf8);
                }

                if(len1 != len2) {
                    fprintf(stderr, "  Strlen and ASN1_STRING size do not match (embedded null?): %d vs %d\n", len2, len1);
                }

                /* If there's a problem with string lengths, then     */
                /* we skip the candidate and move on to the next.     */
                /* Another policy would be to fails since it probably */
                /* indicates the client is under attack.              */
                if(utf8 && len1 && len2 && (len1 == len2)) {
                    fprintf(stdout, "  %s: %s\n", label, utf8);
                    success = 1;
                }

                if(utf8) {
                    OPENSSL_free(utf8), utf8 = NULL;
                }
            }
            else
            {
                fprintf(stderr, "  Unknown GENERAL_NAME type: %d\n", entry->type);
            }
        }

    } while (0);

    if(names)
        GENERAL_NAMES_free(names);

    if(utf8)
        OPENSSL_free(utf8);

    if(!success)
        fprintf(stdout, "  %s: <not available>\n", label);

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


    X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    int err = X509_STORE_CTX_get_error(x509_ctx);
    int depth = X509_STORE_CTX_get_error_depth(x509_ctx);

    X509_NAME* iname = cert ? X509_get_issuer_name(cert) : NULL;
    X509_NAME* sname = cert ? X509_get_subject_name(cert) : NULL;

    if(preverify_ok == 1) {
        printf("Server Certificate Verification passed.\n");

        ASN1_TIME *certNotAfter;
        BIO *bio_stdout;
        certNotAfter = X509_getm_notAfter(cert);

        bio_stdout = BIO_new_fp(stdout, BIO_NOCLOSE);

        //printf("\n  ---------------------------------/n");
        //printf("Server Certificate - Issuer details\n");
        //printf("-----------------------------------\n\n");
        //X509_NAME_print_ex(bio_stdout, iname, 2, XN_FLAG_SEP_MULTILINE);
        printf("\n  ------------------------------------\n");
        printf("  Server Certificate - Subject details\n");
        printf("  ------------------------------------\n\n");
        X509_NAME_print_ex(bio_stdout, sname, 2, XN_FLAG_SEP_MULTILINE);

        printf("\n\nServer Certificate Expiry date:- ");
        ASN1_TIME_print(bio_stdout, certNotAfter);
        printf("\n\n");

        int pDay=0, pSec=0;

        // Passing NULL as first value sets it to current time
        ASN1_TIME_diff(&pDay,  &pSec, NULL, certNotAfter);

        if(pDay <= 30) {
            printf("\n!!!! SERVER CERTIFICATE EXPIRES IN %d DAYS !!!!\n", pDay);
        }

        ASN1_STRING_free(certNotAfter);
        BIO_free(bio_stdout);

    } else {
        // TODO - anyone know why this outputs twice on incorrect inputs?
        if(err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) {
            char answer;
            printf("\nWarning: Server Certificate is self-signed. You should only proceed if you trust this server. Proceed? (Y/n): \n");
            while(1){
                scanf("%c", &answer);
                if (answer == 'Y'){
                    return 1;
                }else if (answer == 'n'){
                    exit(EXIT_FAILURE);
                }else{
                    printf("\nPlease enter 'Y' to proceed or 'n' to abort. (Y/n): \n");
                }
            }
        }

        if(err == X509_V_ERR_CERT_REVOKED) {
            printf("Important: Server Certificate has been revoked and cannot be trusted.\nTerminating TLS connection attempt.\n");
            exit(EXIT_FAILURE);
        }

        //TODO - uncomment once hostnames & certificates are matched up
        //if(err == X509_V_ERR_HOSTNAME_MISMATCH) {
        //    printf("Important: Server Certificate does not match the hostname; Connection is not secure.\nTerminating TLS connection attempt.\n");
        //    exit(EXIT_FAILURE);
        //}



        printf("Verification failed: %s \n",
            X509_verify_cert_error_string(err));
    }
}





/*****************************************************************************************
 *
 * Function:            verify_callback()
 *
 * Description:         Verify Callback code taken from OpenSSL Wiki
 *                      (Delete if unused)
 *
 *****************************************************************************************/
int verify_callback(int preverify, X509_STORE_CTX* x509_ctx)
{
    /* For error codes, see http://www.openssl.org/docs/apps/verify.html  */

    int depth = X509_STORE_CTX_get_error_depth(x509_ctx);
    int err = X509_STORE_CTX_get_error(x509_ctx);

    X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    X509_NAME* iname = cert ? X509_get_issuer_name(cert) : NULL;
    X509_NAME* sname = cert ? X509_get_subject_name(cert) : NULL;

    fprintf(stdout, "verify_callback (depth=%d)(preverify=%d)\n", depth, preverify);

    /* Issuer is the authority we trust that warrants nothing useful */
    print_cn_name("Issuer (cn)", iname);

    /* Subject is who the certificate is issued to by the authority  */
    print_cn_name("Subject (cn)", sname);

    if(depth == 0) {
        /* If depth is 0, its the server's certificate. Print the SANs */
        print_san_name("Subject (san)", cert);
    }

    if(preverify == 0)
    {
        if(err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY)
            fprintf(stdout, "  Error = X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY\n");
        else if(err == X509_V_ERR_CERT_UNTRUSTED)
            fprintf(stdout, "  Error = X509_V_ERR_CERT_UNTRUSTED\n");
        else if(err == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN)
            fprintf(stdout, "  Error = X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN\n");
        else if(err == X509_V_ERR_CERT_NOT_YET_VALID)
            fprintf(stdout, "  Error = X509_V_ERR_CERT_NOT_YET_VALID\n");
        else if(err == X509_V_ERR_CERT_HAS_EXPIRED)
            fprintf(stdout, "  Error = X509_V_ERR_CERT_HAS_EXPIRED\n");
        else if(err == X509_V_OK)
            fprintf(stdout, "  Error = X509_V_OK\n");
        else
            fprintf(stdout, "  Error = %d\n", err);
    }

#if !defined(NDEBUG)
    return 1;
#else
    return preverify;
#endif
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
