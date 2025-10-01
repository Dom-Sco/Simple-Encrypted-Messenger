#ifndef NETWORKING_H
#define NETWORKING_H

#include <sqlite3.h>
#include <glib.h> // For gboolean and g_idle_add

// Function to send a message to an IP address over the network
int send_message_over_network(const char *ip, const char *message, const char *sender_pubkey, int receiver_id);

// Starts the message-receiving server in a background thread
void start_message_server(sqlite3 *db);

// Called by the GTK main loop to update the UI when a new message is received
gboolean notify_incoming_message(gpointer data);

#endif
