# include "server.h"

void init_party(OQS_KEM *kem, Party *party) {
    for (int i = 0; i < GROUP_SIZE; i++) {
        party[i].commitments = malloc(sizeof(Commitment) * GROUP_SIZE);
        party[i].masterkey = malloc(sizeof(MasterKey) * GROUP_SIZE);
        party[i].pids = malloc(sizeof(Pid) * GROUP_SIZE);
        party[i].coins = malloc(sizeof(Coins) * GROUP_SIZE);
        party[i].xs = malloc(sizeof(X) * GROUP_SIZE);
        for (int j = 0; j < GROUP_SIZE; j++) {
            char pid[PID_LENGTH];
            sprintf(pid, "%s %d", "Party", j);
            memcpy(party[i].pids[j], pid, PID_LENGTH);
        }

        // const int DEM_LEN = kem->length_shared_secret + sizeof(int);
        const int COMMITMENTCOINSBYTES = AES_256_IVEC_LENGTH + kem->length_coins;

        for (int j = 0; j < GROUP_SIZE; j++) {
            init_commitment(kem, &party[i].commitments[j]);
            party[i].coins[j] = malloc(COMMITMENTCOINSBYTES);
            init_to_zero(party[i].coins[j], COMMITMENTCOINSBYTES);
            party[i].masterkey[j] = malloc(kem->length_shared_secret);
            init_to_zero(party[i].masterkey[j], kem->length_shared_secret);
            party[i].xs[j] = malloc(kem->length_shared_secret);
            init_to_zero(party[i].xs[j], kem->length_shared_secret);
        }

        party[i].sid = malloc(kem->length_shared_secret);
        party[i].sk  = malloc(kem->length_shared_secret);
        party[i].key_left = malloc(kem->length_shared_secret);
        party[i].key_right = malloc(kem->length_shared_secret);
        init_to_zero(party[i].sid, kem->length_shared_secret);
        init_to_zero(party[i].sk, kem->length_shared_secret);
        init_to_zero(party[i].key_left, kem->length_shared_secret);
        init_to_zero(party[i].key_right, kem->length_shared_secret);

        party[i].public_key = malloc(kem->length_public_key);
        party[i].secret_key  = malloc(kem->length_secret_key);
        init_to_zero(party[i].public_key, kem->length_public_key);
        init_to_zero(party[i].secret_key, kem->length_secret_key);

        party[i].acc = 0;
        party[i].term = 0;
    }
}

// void update_left_right_keys(Party *party, int party_num, OQS_KEM *kem) {
//     return;
// }

void free_party(Party *party, int idx, int party_num) {
    for (int i = 0; i < party_num; i++) {
      free(party[idx].coins[i]);
      free(party[idx].masterkey[i]);
      free(party[idx].xs[i]);
    }

    free(party[idx].masterkey);
    free(party[idx].pids);
    free(party[idx].coins);
    free(party[idx].xs);
    free(party[idx].sid);
    free(party[idx].sk);
    free(party[idx].key_left);
    free(party[idx].key_right);
    free(party[idx].public_key);
    free(party[idx].secret_key);
}


int main(int argc, char** argv) {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    int party_num = 0;
    int port;
    int file_descriptor[GROUP_SIZE];

    for (int i = 0; i < GROUP_SIZE; i++) {
        file_descriptor[i] = -1;
    }

    if (argc != 2) {
        port = PORT;
    } else {
        port = atoi(argv[1]);
    }

    Party *party = malloc(sizeof(Party) * GROUP_SIZE);
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

    // Create socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Set socket options
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    // Bind the socket to the network address and port
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    // Listen for incoming connections
    if (listen(server_fd, GROUP_SIZE) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d\n", port);

    // Accept and handle incoming connections
    while(1) {
        
        if (party_num == GROUP_SIZE) {
            printf("All parties have joined the group...\n");
        } else {
            printf("Waiting for parties to join...\n");
            if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
                perror("accept failed");
                exit(EXIT_FAILURE);
            }

            printf("Initializing party %d...\n", party_num);
            init_party(kem, party);
            OQS_KEM_keypair(kem, party[party_num].public_key, party[party_num].secret_key);
            file_descriptor[party_num] = new_socket;

            printf("Party %d joined the group\n", party_num);

            // Send response
            char hex_key[kem->length_public_key * 2 + 1];

            for (size_t i = 0; i < kem->length_public_key; i++) {
                sprintf(hex_key + (i * 2), "%02x", party[party_num].public_key[i]);
            }
            printf("Sending public key to party %d...\n", party_num);
            // printf("encap: %s\n", hex_key);
            send(new_socket, hex_key, strlen(hex_key), 0);
            memset(hex_key, 0, kem->length_public_key * 2 + 1);
            

            char hex_secret_key[kem->length_secret_key * 2 + 1];

            for (size_t i = 0; i < kem->length_secret_key; i++) {
                sprintf(hex_secret_key + (i * 2), "%02x", party[party_num].secret_key[i]);
            }
            // printf("decap: %s\n", hex_secret_key);
            send(new_socket, hex_secret_key, strlen(hex_secret_key), 0);
            memset(hex_secret_key, 0, kem->length_secret_key * 2 + 1);

            party_num++;
            // TODO: construct this block to a function returning boolean to regenerate 
            // when fails
            if (party_num > 1) {
                printf("Group formed, computing keys...\n");
                print_party(kem, party, 0, party_num, 50);
                compute_left_right_keys(kem, party, party_num);
                print_party(kem, party, 0, party_num, 50);
                compute_xs_commitments(kem, party, party_num, kem->length_shared_secret);
                print_party(kem, party, 0, party_num, 50);

                for (int i = 0; i < party_num; i++) {
                    int res = check_xs(kem, party, i, party_num, kem->length_shared_secret); // Check Xi
                    int result = check_commitments(party, i, party_num, kem->length_shared_secret);
                    if (res == 0 || result == 0) {
                        // TODO: change the structure of party array and fd array
                        // Maybe by link list?
                        printf("Party %d is not valid...\n", i);
                        file_descriptor[i] = -1;
                        party_num--;
                        free_party(party, i, party_num);
                        close(file_descriptor[i]);
                    }
                }
                // Master Key
                compute_masterkey(kem, party, party_num, kem->length_shared_secret);
                // Compute session key and session identifier
                compute_sk_sid(kem, party, party_num, kem->length_shared_secret);
                
                for (int i = 0; i < party_num; i++) {
                    char hex_session_key[kem->length_shared_secret * 2 + 1];
                    for (size_t j = 0; j < kem->length_shared_secret; j++) {
                        sprintf(hex_session_key + (j * 2), "%02x", party[i].sk[j]);
                    }

                    send(file_descriptor[i], hex_session_key, strlen(hex_session_key), 0);
                    memset(hex_session_key, 0, kem->length_shared_secret * 2 + 1);
                }
            }
        }
    }

    close(server_fd);
    for (int i = 0; i < party_num; i++) {
        close(file_descriptor[i]);
    }
    return 0;
}