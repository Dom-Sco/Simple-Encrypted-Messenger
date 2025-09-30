// messaging.h
#ifndef MESSAGING_H
#define MESSAGING_H

#include <gtk/gtk.h>
#include <sqlite3.h>

int init_message_db(sqlite3 *db);
gboolean send_message(sqlite3 *db, int contact_id, const char *message);
void load_message_history(sqlite3 *db, int contact_id, GtkTextBuffer *buffer);

#endif
