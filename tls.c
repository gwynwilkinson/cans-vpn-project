#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }

void processRequest(SSL* ssl, int sock); // Defined in Listing 19.12

int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx){
    char  buf[300];

    X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    X509_NAME_oneline(X509_get_subject_name(cert), buf, 300);
    printf("subject= %s\n", buf);

    if (preverify_ok == 1) {
       printf("Verification passed.\n");
    } else {
       int err = X509_STORE_CTX_get_error(x509_ctx);
       printf("Verification failed: %s.\n", X509_verify_cert_error_string(err));
    }
}

SSL *init_TLS(){
    SSL_METHOD *meth;
    SSL_CTX* ctx;
    SSL *tls;
    int err;
    // Step 1: SSL context initialization
    meth = (SSL_METHOD *)TLS_method();
    ctx = SSL_CTX_new(meth);
    //SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
    // Step 2: Set up the server certificate and private key
    SSL_CTX_use_certificate_file(ctx, "./cert_server/server-cert.pem", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, "./cert_server/server-key.pem", SSL_FILETYPE_PEM);
    // Step 3: Create a new SSL structure for a connection
    tls = SSL_new (ctx);
    return tls;
}
