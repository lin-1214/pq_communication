# include "server.h"


SSL_CTX* init_server_CTX(void) {   
    SSL_CTX *ctx;							
 
    OpenSSL_add_all_algorithms();
    OQS_init();
    SSL_load_error_strings();

    ctx = SSL_CTX_new(TLS_server_method());

    if ( ctx == NULL ) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    
    return ctx;
}

void load_certificates(SSL_CTX* ctx, char* CertFile, char* KeyFile) {
    
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    
    if ( !SSL_CTX_check_private_key(ctx) ) {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}

void generate_cert_and_key(SSL_CTX *ctx, char *public_key, char *secret_key) {
    OQS_STATUS rc;

    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_sphincs_sha256_128f_simple);
    if (sig == NULL) {
        fprintf(stderr, "OQS_SIG_new failed\n");
        exit(1);
    }

    rc = OQS_SIG_keypair(sig, public_key, secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "OQS_SIG_keypair failed\n");
        OQS_SIG_free(sig);
        exit(1);
    }

    OQS_SIG_free(sig);
    // EVP_PKEY_free(pkey);
    // X509_free(x509);
}

int is_root(void) {
    if (getuid() != 0) {
        return 0;
    }
    return 1;
}

int open_listener(int port) {   
    int sd;
    struct sockaddr_in addr;			/*creating the sockets*/
 
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));				/*free output the garbage space in memory*/
    addr.sin_family = AF_INET;				/*getting ip address form machine */
    addr.sin_port = htons(port);			/* converting host bit to n/w bit */
    addr.sin_addr.s_addr = INADDR_ANY;
    if ( bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 ) /* assiging the ip address and port*/
    {
        perror("can't bind port");				/* reporting error using errno.h library */
        abort();						/*if error will be there then abort the process */
    }
    if ( listen(sd, GROUP_SIZE) != 0 )					/*for listening to max of 10 clients in the queue*/
    {
        perror("Can't configure listening port");		/* reporting error using errno.h library */
        abort();						/*if erroor will be there then abort the process */
    }

    return sd;
}

int main(int argc, char *argv[]) {
    
    int server;
    int port;

    uint8_t public_key[PUBLIC_KEY_LENGTH]; // 32 bytes for public key
    uint8_t secret_key[SECRET_KEY_LENGTH]; // 64 bytes for secret key

    // error-proofing
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port> \n", argv[0]);
        return 1;
    }
    
    if (is_root() == 0) {
        fprintf(stderr, "This program must be run as root/sudo user!!\n");
        return 1;
    }

    SSL_library_init();
    port = atoi(argv[1]);

    SSL_CTX* ctx = init_server_CTX();
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    generate_cert_and_key(ctx, public_key, secret_key);

    // print_sk(public_key, PUBLIC_KEY_LENGTH);
    // print_sk(secret_key, SECRET_KEY_LENGTH);
    // printf("Port: %d\n", port);

    load_certificates(ctx, CERT_FILE, KEY_FILE);
    server = open_listener(port); 

    printf("sd: %d\n", server);
    printf("Server listening on port %d\n", port);

    // struct sockaddr_in addr;						
    // socklen_t len = sizeof(addr);
    // SSL *ssl;
 	// listen(server, 32);						
    // int client = accept(server, (struct sockaddr*)&addr, &len);  
    // printf("Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));		
    // ssl = SSL_new(ctx);           
    // SSL_set_fd(ssl, client);

}