#include <errno.h>  
#include <stdio.h>
#include <unistd.h>	
#include <malloc.h>		
#include <string.h>		
#include <arpa/inet.h>		/*for using ascii to network bit*/	
#include <sys/socket.h>		
#include <sys/types.h>		
#include <netinet/in.h>        /* network to asii bit */
#include <resolv.h>		
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include <oqs/oqs.h>

#include "../src/gake.h"
#include "../src/utils.h"

# define BUFFER 1024	
# define GROUP_SIZE 32
# define CERT_FILE "../assets/server_cert.pem"
# define KEY_FILE "../assets/server_key.pem"
# define PUBLIC_KEY_LENGTH 32
# define SECRET_KEY_LENGTH 64

int open_listener(int port);
int is_root(void);
SSL_CTX* init_server_CTX(void);
void load_certificates(SSL_CTX* ctx, char* CertFile, char* KeyFile);
void generate_cert_and_key(SSL_CTX *ctx, char *public_key, char *secret_key);
void show_certs(SSL* ssl);
