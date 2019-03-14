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
#include "logging.h"


#define COOKIE_SECRET_LENGTH 16
unsigned char cookie_secret[COOKIE_SECRET_LENGTH];
int cookie_initialized = 0;

// Support both Elliptic Curve and RSA certificates.
const char *const CHOSEN_CIPHERS = "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:";

SSL_CTX *tls_ctx_init(int protocol, int verify, char *certfile, char *keyfile) {

    SSL_library_init();
    SSL_load_error_strings();
    SSL_CTX *ctx;

    SSL_METHOD *method;
    if (protocol == TCP) {
        method = (SSL_METHOD *) TLS_server_method();
    } else if (protocol == UDP) {
        method = (SSL_METHOD *) DTLS_server_method();
    } else {
        // error handling and logging in line with elsewhere
        LOG(BOTH, "Error: Invalid protocol selected.\n");
        return NULL;
    }

    ctx = SSL_CTX_new(method);
    if (ctx == NULL) {
        //error handling and logging in line with elsewhere
        LOG(BOTH, "Error: Unable to create SSL context.\n");
        return NULL;

    }

    // Define which cipher(s) we want TLS to use
    SSL_CTX_set_cipher_list(ctx, CHOSEN_CIPHERS);
    SSL_CTX_set_verify(ctx, verify, verify_callback);

    // Load and check our cert & key.
    int error = 0;
    error = SSL_CTX_use_certificate_file(ctx, certfile, SSL_FILETYPE_PEM);
    if (error != 1) {
        LOG(BOTH, "Error: Unable to load certificate.\n");
        return NULL;
    }
    error = SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM);
    if (error != 1) {
        LOG(BOTH, "Error: Unable to load private key.\n");
        return NULL;
    }
    error = SSL_CTX_check_private_key(ctx);
    if (error != 1) {
        LOG(BOTH, "Error: Invalid Private Key.\n");
        return NULL;
    }
    // TODO -   Validate server cert on startup
    //          Really hard to figure this out because there's no documentation or examples
    //          Delete this if we don't figure it out, add to our report.
    return ctx;
}


int tls_init(tlsSession *session, bool isServer, int protocol, int verify, char *serverIP, char *certfile, char *keyfile) {

    SSL_METHOD *method = NULL;
    SSL_library_init();
    SSL_load_error_strings();

    if (isServer && protocol == TCP) {
        method = (SSL_METHOD *) TLS_server_method();
    } else if (isServer && protocol == UDP) {
        method = (SSL_METHOD *) DTLS_server_method();
    } else if (!isServer && protocol == TCP) {
        method = (SSL_METHOD *) TLS_client_method();
    } else if (!isServer && protocol == UDP) {
        method = (SSL_METHOD *) DTLS_client_method();
    } else {
        LOG(BOTH, "Error: Invalid protocol selected.\n");
        return -1;
    }

    session->ctx = SSL_CTX_new(method);
    if (session->ctx == NULL) {
        LOG(BOTH, "Error: Unable to create SSL context.\n");
        return -1;
    }

    SSL_CTX_set_cipher_list(session->ctx, CHOSEN_CIPHERS);

    SSL_CTX_set_verify(session->ctx, verify, clientVerifyCallBack);

    SSL_CTX_load_verify_locations(session->ctx, NULL, "./certs");


    int error = 0;

    error = SSL_CTX_use_certificate_file(session->ctx, certfile, SSL_FILETYPE_PEM);
    if (error != 1) {
        LOG(BOTH, "Error: Unable to load certificate.\n");
        return -1;
    }

    error = SSL_CTX_use_PrivateKey_file(session->ctx, keyfile, SSL_FILETYPE_PEM);
    if (error != 1) {
        LOG(BOTH, "Error: Unable to load private key.\n");
        return -1;
    }

    error = SSL_CTX_check_private_key(session->ctx);
    if (error != 1) {
        LOG(BOTH, "Error: Invalid Private Key.\n");
        return -1;
    }

    session->bio = BIO_new_ssl_connect(session->ctx);
    if (session->bio == NULL) {
        LOG(BOTH, "Error: Unable to create BIO.\n");
        return -1;
    }

    if (!isServer) BIO_set_conn_hostname(session->bio, serverIP);

    BIO_get_ssl(session->bio, &(session->ssl));
    if (session->ssl == NULL) {
        LOG(BOTH, "Error: Unable to create SSL instance.\n");
        return -1;
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
 * Function:            clientVerifyCallBack()
 *
 * Description:         On client connection, this callback is called to
 *                      verify the server certificate.
 *
 *****************************************************************************************/
int clientVerifyCallBack(int preverify_ok, X509_STORE_CTX *x509_ctx) {


    X509 *cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    int err = X509_STORE_CTX_get_error(x509_ctx);
    int depth = X509_STORE_CTX_get_error_depth(x509_ctx);

    X509_NAME *iname = cert ? X509_get_issuer_name(cert) : NULL;
    X509_NAME *sname = cert ? X509_get_subject_name(cert) : NULL;

    if (preverify_ok == 1) {
        printf("Server Certificate Verification passed.\n");

        ASN1_TIME *certNotAfter;
        BIO *bio_stdout;
        certNotAfter = X509_getm_notAfter(cert);

        bio_stdout = BIO_new_fp(stdout, BIO_NOCLOSE);

        printf("\n-----------------------------------\n");
        printf("Server Certificate - Issuer details\n");
        printf("-----------------------------------\n\n");
        X509_NAME_print_ex(bio_stdout, iname, 2, XN_FLAG_SEP_MULTILINE);

        printf("\n\nServer Certificate Expiry date:- ");
        ASN1_TIME_print(bio_stdout, certNotAfter);
        printf("\n\n");

        int pDay = 0, pSec = 0;

        // Passing NULL as first value sets it to current time
        ASN1_TIME_diff(&pDay, &pSec, NULL, certNotAfter);

        if (pDay <= 30) {
            printf("\n!!!! SERVER CERTIFICATE EXPIRES IN %d DAYS !!!!\n", pDay);
        }

        ASN1_STRING_free(certNotAfter);
        BIO_free(bio_stdout);

    } else {
        if (err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) {
            char answer;
            int status, temp;

            printf("Warning: Server Certificate is self-signed. You should only proceed if you trust this server. Proceed? (Y/n): \n");

            status = scanf("%c", &answer);

            // Handle any input error
            while ((status != 1) || ((answer != 'Y') && (answer != 'n'))) {
                while ((temp = getchar()) != EOF && temp != '\n');
                printf("Invalid entry. Please enter 'Y' to proceed or 'n' to abort. (Y/n): \n");
                status = scanf("%c", &answer);
            }

            fflush(stdin);

            if (answer == 'Y') {
                printf("Proceeding as directed by user...\n");
                return 1;
            } else if (answer == 'n') {
                printf("Aborting as directed by user...\n");
                exit(EXIT_FAILURE);
            }

        }

        if (err == X509_V_ERR_CERT_REVOKED) {
            printf("Important: Server Certificate has been revoked and cannot be trusted.\nTerminating TLS connection attempt.\n");
            exit(EXIT_FAILURE);
        }

        //TODO - uncomment once hostnames & certificates are matched up
        //if(err == X509_V_ERR_HOSTNAME_MISMATCH) {
        //    printf("Important: Server Certificate does not match the hostname; Connection is not secure.\nTerminating TLS connection attempt.\n");
        //    exit(EXIT_FAILURE);
        //}



        printf("Verification failed: %s \n", X509_verify_cert_error_string(err));
    }
}

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
 * Function:            verify_callback()
 *
 * Description:         Verify Callback code taken from OpenSSL Wiki
 *                      Called by Server to verify client certificates
 *
 *****************************************************************************************/
int verify_callback(int preverify, X509_STORE_CTX *x509_ctx) {
    /* For error codes, see http://www.openssl.org/docs/apps/verify.html  */

    X509 *cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    int depth = X509_STORE_CTX_get_error_depth(x509_ctx);
    int err = X509_STORE_CTX_get_error(x509_ctx);

    X509_NAME *iname = cert ? X509_get_issuer_name(cert) : NULL;
    X509_NAME *sname = cert ? X509_get_subject_name(cert) : NULL;

    printf("verify_callback (depth=%d)(preverify=%d)\n", depth, preverify);

    if (preverify == 1) {
        LOG(BOTH, "Client Certificate Verification passed.\n");

        ASN1_TIME *certNotAfter;
        BIO *bio_stdout;
        certNotAfter = X509_getm_notAfter(cert);

        bio_stdout = BIO_new_fp(stdout, BIO_NOCLOSE);

        LOG(BOTH, "------------------------------------\n");
        LOG(BOTH, "Client Certificate - Subject details\n");
        LOG(BOTH, "------------------------------------\n\n");
        //TODO - LOG X509_NAME_print_ex to file
        //X509_NAME_print_ex(bio_stdout, sname, 2, XN_FLAG_SEP_MULTILINE);

        LOG(BOTH, "\n\nServer Certificate Expiry date:- ");

        //TODO - LOG ASN1_TIME_print to file
        ASN1_TIME_print(bio_stdout, certNotAfter);

        printf("\n\n");

        int pDay = 0, pSec = 0;

        // Passing NULL as first value sets it to current time
        ASN1_TIME_diff(&pDay, &pSec, NULL, certNotAfter);

        if (pDay <= 30) {
            LOG(BOTH, "\n!!!! CLIENT CERTIFICATE EXPIRES IN %d DAYS !!!!\n", pDay);
        }

        ASN1_STRING_free(certNotAfter);
        BIO_free(bio_stdout);

    } else {
        LOG(BOTH, "Verification failed: %s \n", X509_verify_cert_error_string(err));
        return preverify;
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
int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len) {
    unsigned char *buffer, result[EVP_MAX_MD_SIZE];
    unsigned int length = 0, resultlength;
    union {
        struct sockaddr_storage ss;
        struct sockaddr_in6 s6;
        struct sockaddr_in s4;
    } peer;

    /* Initialize a random secret */
    if (!cookie_initialized) {
        if (!RAND_bytes(cookie_secret, COOKIE_SECRET_LENGTH)) {
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
    buffer = (unsigned char *) OPENSSL_malloc(length);

    if (buffer == NULL) {
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
    HMAC(EVP_sha1(), (const void *) cookie_secret, COOKIE_SECRET_LENGTH,
         (const unsigned char *) buffer, length, result, &resultlength);
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
int verify_cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len) {
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
    buffer = (unsigned char *) OPENSSL_malloc(length);

    if (buffer == NULL) {
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
    HMAC(EVP_sha1(), (const void *) cookie_secret, COOKIE_SECRET_LENGTH,
         (const unsigned char *) buffer, length, result, &resultlength);
    OPENSSL_free(buffer);

    if (cookie_len == resultlength && memcmp(result, cookie, resultlength) == 0)
        return 1;

    return 0;
}
