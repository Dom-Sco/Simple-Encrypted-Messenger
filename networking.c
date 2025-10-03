#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sqlite3.h>

#include "messaging.h"
#include "crypto_helpers.h"
#include "crypto_utils.h"  
#include "identity.h"     


#define SERVER_PORT 4444
#define BUFFER_SIZE 2048

GHashTable *messaging_windows = NULL;

static sqlite3 *global_db = NULL;  // So the server thread can access the database

/**
 * Send a message to a given IP address over the network.
 */
int send_message_over_network(const char *ip, const char *plaintext, const char *recipient_pubkey_file, int receiver_id, const char *sender_pubkey_file) {
    int sockfd;
    struct sockaddr_in server_addr;

    // === Step 1: Load Keys ===

    // Build full path for sender's private key (hardcoded path)
    EVP_PKEY *sender_privkey = load_private_key_from_pem("keys/self/self_priv.pem");
    if (!sender_privkey) {
        fprintf(stderr, "[send_message_over_network] Failed to load sender private key\n");
        return 0;
    }

    // Build full path for recipient's public key
    char recipient_key_path[256];
    snprintf(recipient_key_path, sizeof(recipient_key_path), "keys/contacts/%s", recipient_pubkey_file);

    EVP_PKEY *recipient_pubkey = load_public_key_from_pem(recipient_key_path);
    if (!recipient_pubkey) {
        fprintf(stderr, "[send_message_over_network] Failed to load recipient public key from file: %s\n", recipient_key_path);
        EVP_PKEY_free(sender_privkey);
        return 0;
    }

    // === Step 2: Encrypt message ===
    SecureMessage secure_msg;
    if (!build_secure_message_package((const unsigned char *)plaintext, strlen(plaintext),
                                      sender_privkey, recipient_pubkey, &secure_msg)) {
        fprintf(stderr, "[send_message_over_network] Failed to build secure message package\n");
        EVP_PKEY_free(sender_privkey);
        EVP_PKEY_free(recipient_pubkey);
        return 0;
    }

    EVP_PKEY_free(sender_privkey);
    EVP_PKEY_free(recipient_pubkey);

    // === Step 3: Base64 encode ===
    char *b64_encoded = base64_encode(secure_msg.data, secure_msg.length);
    free(secure_msg.data);

    if (!b64_encoded) {
        fprintf(stderr, "[send_message_over_network] Failed to base64 encode secure message\n");
        return 0;
    }

    // === Step 4: Format message ===
    // Format: <sender_pubkey_filename>\n<receiver_id>\n<base64_data>\n
    char buffer[BUFFER_SIZE];
    snprintf(buffer, sizeof(buffer), "%s\n%d\n%s\n", sender_pubkey_file, receiver_id, b64_encoded);
    free(b64_encoded);

    // === Step 5: Send over network ===
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("[send_message_over_network] Socket creation failed");
        return 0;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);

    if (inet_pton(AF_INET, ip, &server_addr.sin_addr) <= 0) {
        perror("[send_message_over_network] Invalid IP address");
        close(sockfd);
        return 0;
    }

    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("[send_message_over_network] Connection failed");
        close(sockfd);
        return 0;
    }

    if (write(sockfd, buffer, strlen(buffer)) < 0) {
        perror("[send_message_over_network] Write failed");
        close(sockfd);
        return 0;
    }

    close(sockfd);
    return 1;
}


/*
int send_message_over_network(const char *ip, const char *plaintext, const char *recipient_pubkey_file, int receiver_id, const char *sender_pubkey_file) {
    int sockfd;
    struct sockaddr_in server_addr;

    // === Step 1: Load keys ===
    EVP_PKEY *sender_privkey = load_private_key_from_pem("keys/self/self_priv.pem");
    if (!sender_privkey) {
        fprintf(stderr, "Failed to load sender private key\n");
        return 0;
    }

    EVP_PKEY *recipient_pubkey = load_contact_public_key(recipient_pubkey_file);
    if (!recipient_pubkey) {
        fprintf(stderr, "Failed to load recipient public key: %s\n", recipient_pubkey_file);
        EVP_PKEY_free(sender_privkey);
        return 0;
    }

    // === Step 2: Encrypt ===
    SecureMessage secure_msg;
    if (!build_secure_message_package((const unsigned char *)plaintext, strlen(plaintext),
                                      sender_privkey, recipient_pubkey, &secure_msg)) {
        fprintf(stderr, "Failed to build secure message package\n");
        EVP_PKEY_free(sender_privkey);
        EVP_PKEY_free(recipient_pubkey);
        return 0;
    }

    EVP_PKEY_free(sender_privkey);
    EVP_PKEY_free(recipient_pubkey);

    // === Step 3: Base64 encode ===
    char *b64_encoded = base64_encode(secure_msg.data, secure_msg.length);
    free(secure_msg.data);

    if (!b64_encoded) {
        fprintf(stderr, "Failed to base64 encode secure message\n");
        return 0;
    }

    // === Step 4: Prepare message format ===
    // <sender_pubkey_filename>\n<receiver_id>\n<base64_msg>\n
    char buffer[BUFFER_SIZE];
    snprintf(buffer, sizeof(buffer), "%s\n%d\n%s\n", sender_pubkey_file, receiver_id, b64_encoded);
    free(b64_encoded);

    // === Step 5: Send over network ===
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("[send] Socket creation failed");
        return 0;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);

    if (inet_pton(AF_INET, ip, &server_addr.sin_addr) <= 0) {
        perror("[send] Invalid IP address");
        close(sockfd);
        return 0;
    }

    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("[send] Connection failed");
        close(sockfd);
        return 0;
    }

    if (write(sockfd, buffer, strlen(buffer)) < 0) {
        perror("[send] Write failed");
        close(sockfd);
        return 0;
    }

    close(sockfd);
    return 1;
}
*/

/**
 * Internal thread function to listen for incoming messages.
 */
void *server_thread_func(void *arg) {
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    char buffer[BUFFER_SIZE];
    socklen_t client_len = sizeof(client_addr);

    // Create server socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("[server] Socket creation failed");
        return NULL;
    }

    int optval = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("[server] Bind failed");
        close(server_fd);
        return NULL;
    }

    if (listen(server_fd, 5) < 0) {
        perror("[server] Listen failed");
        close(server_fd);
        return NULL;
    }

    printf("[server] Listening on port %d...\n", SERVER_PORT);

    while (1) {
        client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            perror("[server] Accept failed");
            continue;
        }

        memset(buffer, 0, sizeof(buffer));
        ssize_t bytes = read(client_fd, buffer, sizeof(buffer) - 1);
        if (bytes <= 0) {
            perror("[server] Read failed");
            close(client_fd);
            continue;
        }

        buffer[bytes] = '\0'; // Ensure null-termination
        printf("[server] Received base64 message (%ld bytes)\n", bytes);

        // 1. Base64 decode to get SecureMessage
        size_t msg_bin_len = 0;
        unsigned char *msg_bin = base64_decode(buffer, &msg_bin_len);
        if (!msg_bin) {
            fprintf(stderr, "[server] Failed to decode base64 message\n");
            close(client_fd);
            continue;
        }

        SecureMessage msg = {
            .data = msg_bin,
            .length = msg_bin_len
        };

        // 2. Extract sender info from signed blob
        // We will use the public key signature verification to get sender_pubkey
        EVP_PKEY *sender_pubkey = NULL;
        int sender_id = -1;

        // Loop over contacts to try their public keys
        sqlite3_stmt *stmt;
        const char *query = "SELECT id, pubkey FROM contacts;";
        if (sqlite3_prepare_v2(global_db, query, -1, &stmt, NULL) == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                int contact_id = sqlite3_column_int(stmt, 0);
                const char *pubkey_file = (const char *)sqlite3_column_text(stmt, 1);

                char full_path[256];
                snprintf(full_path, sizeof(full_path), "keys/contacts/%s", pubkey_file);

                EVP_PKEY *key = load_public_key_from_pem(full_path);
                if (!key) continue;

                unsigned char *plaintext = NULL;
                size_t plaintext_len = 0;

                // Try to decrypt with this key
                EVP_PKEY *our_privkey = load_private_key_from_pem("keys/self/self_priv.pem");
                if (!our_privkey) {
                    fprintf(stderr, "[server] Failed to load our private key\n");
                    EVP_PKEY_free(key);
                    break;
                }

                if (parse_and_decrypt_secure_message(&msg, our_privkey, key, &plaintext, &plaintext_len)) {
                    // Found correct sender
                    sender_id = contact_id;
                    sender_pubkey = key; // Don't free
                    sqlite3_finalize(stmt);

                    // Save message to DB
                    int our_id = get_our_id(global_db); // implement this if needed
                    send_message(global_db, sender_id, our_id, (char *)plaintext);

                    // Notify UI
                    NotifyMessageData *msg_data = g_malloc(sizeof(NotifyMessageData));
                    msg_data->sender_id = sender_id;
                    msg_data->receiver_id = our_id;
                    msg_data->message = g_strdup((char *)plaintext);

                    g_idle_add(notify_incoming_message, msg_data);
                    free(plaintext);
                    EVP_PKEY_free(our_privkey);
                    break;
                }

                // Not a match
                EVP_PKEY_free(key);
                EVP_PKEY_free(our_privkey);
            }
            sqlite3_finalize(stmt);
        }

        if (sender_id == -1) {
            fprintf(stderr, "[server] Could not verify sender — message discarded.\n");
        }

        free(msg_bin);
        close(client_fd);
    }

    close(server_fd);
    return NULL;
}

/**
 * Start the background message server.
 */
void start_message_server(sqlite3 *db) {
    global_db = db;

    pthread_t thread_id;
    if (pthread_create(&thread_id, NULL, server_thread_func, NULL) != 0) {
        perror("[server] Failed to start server thread");
    } else {
        pthread_detach(thread_id); // Let the thread run independently
    }
}