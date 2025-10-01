// messaging.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <gtk/gtk.h>

int init_message_db(sqlite3 *db) {
    const char *sql =
        "DROP TABLE IF EXISTS messages;"
        "CREATE TABLE messages ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "sender_id INTEGER NOT NULL,"
        "receiver_id INTEGER NOT NULL,"
        "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,"
        "message TEXT NOT NULL,"
        "FOREIGN KEY(sender_id) REFERENCES contacts(id),"
        "FOREIGN KEY(receiver_id) REFERENCES contacts(id)"
        ");";

    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error (init_message_db): %s\n", err);
        sqlite3_free(err);
        return rc;
    }

    return SQLITE_OK;
}

/* Save a message to the database */
gboolean send_message(sqlite3 *db, int sender_id, int receiver_id, const char *message) {
    const char *sql = "INSERT INTO messages (sender_id, receiver_id, message, timestamp) VALUES (?, ?, ?, datetime('now'));";
    sqlite3_stmt *stmt;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        return FALSE;
    }

    sqlite3_bind_int(stmt, 1, sender_id);
    sqlite3_bind_int(stmt, 2, receiver_id);
    sqlite3_bind_text(stmt, 3, message, -1, SQLITE_TRANSIENT);

    gboolean success = TRUE;
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        fprintf(stderr, "Failed to insert message: %s\n", sqlite3_errmsg(db));
        success = FALSE;
    }

    sqlite3_finalize(stmt);
    return success;
}


// Utility to append formatted message to the text buffer
void append_message(GtkTextBuffer *buffer, const char *sender, const char *message) {
    GtkTextIter end;
    gtk_text_buffer_get_end_iter(buffer, &end);

    gchar *formatted = g_strdup_printf("%s: %s\n", sender, message);
    gtk_text_buffer_insert(buffer, &end, formatted, -1);
    g_free(formatted);
}

/* Load message history into a GtkTextBuffer */
void load_message_history(sqlite3 *db, int self_id, int contact_id, GtkTextBuffer *buffer) {
    const char *sql =
        "SELECT sender_id, message, timestamp FROM messages "
        "WHERE (sender_id = ? AND receiver_id = ?) "
        "   OR (sender_id = ? AND receiver_id = ?) "
        "ORDER BY timestamp ASC;";

    sqlite3_stmt *stmt;

    gtk_text_buffer_set_text(buffer, "", -1);  // Clear previous content

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare load_message_history: %s\n", sqlite3_errmsg(db));
        return;
    }

    sqlite3_bind_int(stmt, 1, self_id);
    sqlite3_bind_int(stmt, 2, contact_id);
    sqlite3_bind_int(stmt, 3, contact_id);
    sqlite3_bind_int(stmt, 4, self_id);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        int sender_id = sqlite3_column_int(stmt, 0);
        const char *message = (const char *)sqlite3_column_text(stmt, 1);
        // const char *timestamp = (const char *)sqlite3_column_text(stmt, 2); // Optional, unused here

        const char *sender_label = (sender_id == self_id) ? "You" : "Them";
        append_message(buffer, sender_label, message);
    }

    sqlite3_finalize(stmt);
}