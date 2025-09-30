#ifndef MESSAGING_H
#define MESSAGING_H

#include <gtk/gtk.h>
#include <sqlite3.h>

// ---- Existing declarations (keep) ----
int init_message_db(sqlite3 *db);
gboolean send_message(sqlite3 *db, int sender_id, int receiver_id, const char *message);
void load_message_history(sqlite3 *db, int self_id, int contact_id, GtkTextBuffer *buffer);

// ---- New types and declarations ----

// Used to track open messaging windows (for live updates)
typedef struct {
    int contact_id;
    GtkWidget *window;
    GtkTextBuffer *history_buffer;
    GtkWidget *entry; // Optional: reference to the entry field
} MessagingWindowData;

// Used for passing messages from networking thread to main thread
typedef struct {
    int sender_id;
    int receiver_id;
    char *message;
} NotifyMessageData;

// Global hash table (in .c file, declared here for external use)
extern GHashTable *messaging_windows;

// Called from networking thread (via g_idle_add) to update UI
gboolean notify_incoming_message(gpointer data);

// Append message to history buffer (helper function)
void append_message(GtkTextBuffer *buffer, const char *sender, const char *message);

#endif // MESSAGING_H
