#include "client.h"

void flush_socket(int sock) {
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    char temp_buffer[BUFFER_SIZE];
    ssize_t bytes_read;
    do {
        bytes_read = recv(sock, temp_buffer, sizeof(temp_buffer), 0);
    } while (bytes_read > 0);

    fcntl(sock, F_SETFL, flags);
}

int main(int argc, char const *argv[]) {
    int sock = 0;
    int port = PORT;
    struct sockaddr_in serv_addr;
    // char buffer[BUFFER_SIZE];
    
    if (argc > 1) {
        port = atoi(argv[1]);
    }

    OQS_KEM *kem;

    if(!OQS_KEM_alg_is_enabled(KEM)) {
        printf("%s is not enabled or does not exist!\n", KEM);
        printf("Available KEM are: \n");
        for (int i = 0; i < OQS_KEM_alg_count(); i++) {
        if(OQS_KEM_alg_is_enabled(OQS_KEM_alg_identifier(i)))
            printf("%s\n", OQS_KEM_alg_identifier(i));
        }
        exit(0);
    } 

    kem = OQS_KEM_new(KEM);
    if(kem == NULL) exit(EXIT_FAILURE);

    char public_key[2*kem->length_public_key+1];
    char secret_key[2*kem->length_secret_key+1];
    char shared_key[2*kem->length_shared_secret+1];

    // Create socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        return -1;
    }
   
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
       
    // Convert IPv4 and IPv6 addresses from text to binary form
    if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }
   
    // Connect to server
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("\nConnection Failed \n");
        return -1;
    }
    
    // Receive first message
    read(sock, public_key, 2*kem->length_public_key+1);
    // printf("Encapsulated key: %s\n", public_key);
    
    read(sock, secret_key, 2*kem->length_secret_key+1);
    // printf("Decapsulated key: %s\n", secret_key);

    struct pollfd fds[2];
    fds[0].fd = sock;
    fds[0].events = POLLIN;
    fds[1].fd = STDIN_FILENO;
    fds[1].events = POLLIN;
    
    while (1) {
        int ret = poll(fds, 2, 100); // 100ms timeout
        
        if (ret < 0) {
            perror("poll error");
            break;
        }
        
        if (ret == 0) {
            // Timeout, no events
            // printf("Waiting for server...\n");
            continue;
        }
        
        if (fds[0].revents & POLLIN) {
            read(sock, shared_key, 2*kem->length_shared_secret+1);
        }
        
        if (fds[1].revents & POLLIN) {
            // TODO: Handle user input
        }
    }
    
    close(sock);
    return 0;
}
