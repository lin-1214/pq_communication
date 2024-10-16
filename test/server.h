#include <errno.h>  
#include <stdio.h>
#include <unistd.h>	
#include <malloc.h>		
#include <string.h>		
#include <arpa/inet.h>	
#include <sys/socket.h>		
#include <sys/types.h>		
#include <netinet/in.h>
#include <resolv.h>		
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include <oqs/oqs.h>

#include "../src/gake.h"
#include "../src/utils.h"

# define BUFFER_SIZE 1024	
# define PORT 8080
# define GROUP_SIZE 32
# define KEM "Kyber512"

# define PUBLIC_KEY_LENGTH 32
# define SECRET_KEY_LENGTH 64

void init_party(OQS_KEM *kem, Party *party, int party_num);
void update_left_right_keys(Party *party, int party_num, OQS_KEM *kem);
void free_party(Party *party, int idx, int party_num);