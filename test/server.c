# include "server.h"

void init_party(OQS_KEM *kem, Party *party, int party_num) {
    party[party_num].commitments = malloc(sizeof(Commitment) * GROUP_SIZE);
    party[party_num].masterkey = malloc(sizeof(MasterKey) * GROUP_SIZE);
    party[party_num].pids = malloc(sizeof(Pid) * GROUP_SIZE);
    party[party_num].coins = malloc(sizeof(Coins) * GROUP_SIZE);
    party[party_num].xs = malloc(sizeof(X) * GROUP_SIZE);
    for (int j = 0; j < GROUP_SIZE; j++) {
      char pid[PID_LENGTH];
      sprintf(pid, "%s %d", "Party", j);
      memcpy(party[party_num].pids[j], pid, PID_LENGTH);
    }

    // const int DEM_LEN = kem->length_shared_secret + sizeof(int);
    const int COMMITMENTCOINSBYTES = AES_256_IVEC_LENGTH + kem->length_coins;

    for (int j = 0; j < GROUP_SIZE; j++) {
      init_commitment(kem, &party[party_num].commitments[j]);
      party[party_num].coins[j] = malloc(COMMITMENTCOINSBYTES);
      init_to_zero(party[party_num].coins[j], COMMITMENTCOINSBYTES);
      party[party_num].masterkey[j] = malloc(kem->length_shared_secret);
      init_to_zero(party[party_num].masterkey[j], kem->length_shared_secret);
      party[party_num].xs[j] = malloc(kem->length_shared_secret);
      init_to_zero(party[party_num].xs[j], kem->length_shared_secret);
    }

    party[party_num].sid = malloc(kem->length_shared_secret);
    party[party_num].sk  = malloc(kem->length_shared_secret);
    party[party_num].key_left = malloc(kem->length_shared_secret);
    party[party_num].key_right = malloc(kem->length_shared_secret);
    init_to_zero(party[party_num].sid, kem->length_shared_secret);
    init_to_zero(party[party_num].sk, kem->length_shared_secret);
    init_to_zero(party[party_num].key_left, kem->length_shared_secret);
    init_to_zero(party[party_num].key_right, kem->length_shared_secret);

    party[party_num].public_key = malloc(kem->length_public_key);
    party[party_num].secret_key  = malloc(kem->length_secret_key);
    init_to_zero(party[party_num].public_key, kem->length_public_key);
    init_to_zero(party[party_num].secret_key, kem->length_secret_key);

    OQS_KEM_keypair(kem,
                    party[party_num].public_key,
                    party[party_num].secret_key);

    party[party_num].acc = 0;
    party[party_num].term = 0;
}

int main(int argc, char** argv) {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    int party_num = 0;
    int port;

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
            init_party(kem, party, party_num);
            party_num++;

            printf("Party %d joined the group\n", party_num - 1);

            // Send response
            char hex_key[kem->length_public_key * 2 + 1];
            for (size_t i = 0; i < kem->length_public_key; i++) {
                sprintf(hex_key + (i * 2), "%02x", party[party_num - 1].public_key[i]);
            }
            send(new_socket, hex_key, strlen(hex_key), 0);

            char hex_secret_key[kem->length_secret_key * 2 + 1];
            for (size_t i = 0; i < kem->length_secret_key; i++) {
                sprintf(hex_secret_key + (i * 2), "%02x", party[party_num - 1].secret_key[i]);
            }

            send(new_socket, hex_secret_key, strlen(hex_secret_key), 0);
        }
    }

    close(server_fd);
    return 0;
}