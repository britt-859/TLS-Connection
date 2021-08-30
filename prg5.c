#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
     BIO *sbio;
     int len;
     char tmpbuf[1024];
     SSL_CTX *ctx;
     SSL *ssl;

     // Quick test for two command-line arguments
     // argv[0] is program name, argv[1] is address,
     // argv[2] is resource. Each is a C string.  /* XXX Seed the PRNG if needed. */
     if (argc != 3) {
         printf("usage: %s address resource\n", argv[0]);
         return 0;
     }

     char hostName[strlen(argv[1]) + 1];
     char hostNameAndPort[strlen(argv[1]) + 7];
     char get[26 + strlen(argv[2])];
     char host[9 + strlen(argv[1])];
     strcpy(hostName, argv[1]);
     strcpy(hostNameAndPort, argv[1]);
     strcat(hostNameAndPort, ":https");
     strcpy(get, "GET ");
     strcat(get, argv[2]);
     strcat(get, " HTTP/1.1\r\n");
     strcpy(host, "Host: ");
     strcat(host, argv[1]);
     strcat(host, "\r\n");
     char getReq[(strlen(host) + strlen(get) + 22)];
     strcpy(getReq, get);
     strcat(getReq, host);
     strcat(getReq, "Connection: close\r\n\r\n");

     //Initializing OpenSSL
     SSL_load_error_strings();
     ERR_load_BIO_strings();
     OpenSSL_add_all_algorithms();

     ctx = SSL_CTX_new(SSLv23_client_method());

     //Load a trusted store

     if(! SSL_CTX_load_verify_locations(ctx, "/etc/ssl/certs/ca-certificates.crt", NULL)) {
         printf("Failed trusted cert store load");
         return 0;
     }
     /* XXX Set verify paths and mode here. */


     sbio = BIO_new_ssl_connect(ctx);

     BIO_set_conn_hostname(sbio, hostNameAndPort);
     BIO_get_ssl(sbio, &ssl);
     if (!(ssl != NULL)) {
         printf("Can't locate SSL pointer\n");
         BIO_free_all(sbio);
         return 0;
     }
     SSL_set_tlsext_host_name(ssl, hostName);

     if (BIO_do_connect(sbio) <= 0) {
         printf("Error connecting to server\n");
         BIO_free_all(sbio);
         return 0;
     }

     if (BIO_do_handshake(sbio) <= 0) {
         printf("Failed handshake\n");
         BIO_free_all(sbio);
         return 0;
     }

     //verify and print cert info
     X509* cert = SSL_get_peer_certificate(ssl);
     if(cert) { X509_free(cert); } /* Free immediately */
     if(NULL == cert) {
         BIO_free_all(sbio);
         printf("Cert not presented\n");
         return 0;
     }

     if (SSL_get_verify_result(ssl) != X509_V_OK) {
         printf("%s\n", X509_verify_cert_error_string(SSL_get_verify_result(ssl)));
         BIO_free_all(sbio);
         return 0;
     }

     char *subj = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
     char *issuer = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
     printf("%s\n", subj);
     printf("%s\n", issuer);
  
     //print html info

     BIO_puts(sbio, getReq);
     for(;;) {
         len = BIO_read(sbio, tmpbuf, 1024);
         if (len <= 0) {
             break;
         }
        printf("%s", tmpbuf);
     }

     BIO_free_all(sbio);
     OPENSSL_free(ctx);
     OPENSSL_free(subj);
     OPENSSL_free(issuer);
     return 0;
}
