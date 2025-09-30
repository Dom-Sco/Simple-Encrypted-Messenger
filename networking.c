#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sqlite3.h>

#include "messaging.h"

#define SERVER_PORT 4444
#define BUFFER_SIZE 2048

static sqlite3 *global_db = NULL;  // So the server thread can access the database

/**
 * Send a message to a given IP address over the network.
 */
int send_message_over_network(const char *ip, const char *message, int contact_id) {
    int sockfd;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];

    // Prepare message format: <contact_id>\n<message>\n
    snprintf(buffer, sizeof(buffer), "%d\n%s\n", contact_id, message);

    // Create socket
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

    // Connect
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("[send] Connection failed");
        close(sockfd);
        return 0;
    }

    // Send data
    if (write(sockfd, buffer, strlen(buffer)) < 0) {
        perror("[send] Write failed");
        close(sockfd);
        return 0;
    }

    close(sockfd);
    return 1;
}

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

    // Allow quick reuse of port
    int optval = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    // Bind
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

        buffer[bytes] = '\0';

        // Expecting format: <contact_id>\n<message>\n
        char *newline = strchr(buffer, '\n');
        if (newline) {
            *newline = '\0';
            int contact_id = atoi(buffer);
            const char *msg_text = newline + 1;

            // Strip trailing newline (optional)
            char *msg_end = strchr(msg_text, '\n');
            if (msg_end) *msg_end = '\0';

            printf("[server] Received message for contact %d: %s\n", contact_id, msg_text);

            // Save to DB
            send_message(global_db, contact_id, msg_text);
        } else {
            fprintf(stderr, "[server] Invalid message format\n");
        }

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