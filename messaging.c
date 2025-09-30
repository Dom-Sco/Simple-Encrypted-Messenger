// messaging.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <gtk/gtk.h>

/* Initialize the messages table */
int init_message_db(sqlite3 *db) {
    const char *sql =
        "CREATE TABLE IF NOT EXISTS messages ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "contact_id INTEGER NOT NULL,"
        "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,"
        "message TEXT NOT NULL,"
        "FOREIGN KEY(contact_id) REFERENCES contacts(id)"
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
gboolean send_message(sqlite3 *db, int contact_id, const char *message) {
    const char *sql = "INSERT INTO messages (contact_id, message) VALUES (?, ?);";
    sqlite3_stmt *stmt;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare send_message: %s\n", sqlite3_errmsg(db));
        return FALSE;
    }

    sqlite3_bind_int(stmt, 1, contact_id);
    sqlite3_bind_text(stmt, 2, message, -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return rc == SQLITE_DONE;
}

/* Load message history into a GtkTextBuffer */
void load_message_history(sqlite3 *db, int contact_id, GtkTextBuffer *buffer) {
    const char *sql =
        "SELECT timestamp, message FROM messages "
        "WHERE contact_id = ? ORDER BY timestamp ASC;";

    sqlite3_stmt *stmt;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare load_message_history: %s\n", sqlite3_errmsg(db));
        return;
    }

    sqlite3_bind_int(stmt, 1, contact_id);

    gtk_text_buffer_set_text(buffer, "", -1);  // Clear first
    GtkTextIter end;
    gtk_text_buffer_get_end_iter(buffer, &end);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *timestamp = (const char *)sqlite3_column_text(stmt, 0);
        const char *msg = (const char *)sqlite3_column_text(stmt, 1);

        char line[1024];
        snprintf(line, sizeof(line), "[%s] %s\n", timestamp ? timestamp : "unknown", msg ? msg : "");
        gtk_text_buffer_insert(buffer, &end, line, -1);
    }

    sqlite3_finalize(stmt);
}
