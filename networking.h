#ifndef NETWORKING_H
#define NETWORKING_H

#include <sqlite3.h>

int send_message_over_network(const char *ip, const char *message, int contact_id);
void start_message_server(sqlite3 *db);

#endif
