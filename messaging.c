// messaging.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <gtk/gtk.h>
#include "crypto_utils.h"
#include "crypto_helpers.h"

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
gboolean send_message(sqlite3 *db, int sender_id, int receiver_id, const char *plaintext_msg) {
    // Load sender's private key
    EVP_PKEY *sender_priv = load_private_key_from_pem("keys/self/self_priv.pem");
    if (!sender_priv) {
        fprintf(stderr, "Failed to load sender private key\n");
        return FALSE;
    }

    // Load recipient's public key from file path stored in the DB
    const char *sql_pub = "SELECT pubkey_path FROM contacts WHERE id = ?;";
    sqlite3_stmt *stmt_pub = NULL;
    EVP_PKEY *recipient_pub = NULL;

    if (sqlite3_prepare_v2(db, sql_pub, -1, &stmt_pub, NULL) == SQLITE_OK) {
        sqlite3_bind_int(stmt_pub, 1, receiver_id);

        if (sqlite3_step(stmt_pub) == SQLITE_ROW) {
            const char *pubkey_file_path = (const char *)sqlite3_column_text(stmt_pub, 0);

            // Construct full path: keys/contacts/<filename>
            char full_path[256];
            snprintf(full_path, sizeof(full_path), "keys/contacts/%s", pubkey_file_path);
            recipient_pub = load_public_key_from_pem(full_path);
        }

        sqlite3_finalize(stmt_pub);
    }
    
    if (!recipient_pub) {
        fprintf(stderr, "[send_message] Failed to load recipient public key\n");
        return FALSE;
    }

    // Build secure package
    SecureMessage packaged;
    if (!build_secure_message_package(
            (const unsigned char *)plaintext_msg,
            strlen(plaintext_msg),
            sender_priv,
            recipient_pub,
            &packaged)) {
        fprintf(stderr, "Failed to build secure message package\n");
        EVP_PKEY_free(sender_priv);
        EVP_PKEY_free(recipient_pub);
        return FALSE;
    }

    // Base64 encode
    char *encoded = base64_encode(packaged.data, packaged.length);

    // Store into DB
    const char *sql_insert = "INSERT INTO messages (sender_id, receiver_id, message, timestamp) VALUES (?, ?, ?, datetime('now'));";
    sqlite3_stmt *stmt;

    if (sqlite3_prepare_v2(db, sql_insert, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare INSERT: %s\n", sqlite3_errmsg(db));
        EVP_PKEY_free(sender_priv);
        EVP_PKEY_free(recipient_pub);
        free(packaged.data);
        free(encoded);
        return FALSE;
    }

    sqlite3_bind_int(stmt, 1, sender_id);
    sqlite3_bind_int(stmt, 2, receiver_id);
    sqlite3_bind_text(stmt, 3, encoded, -1, SQLITE_TRANSIENT);

    gboolean success = (sqlite3_step(stmt) == SQLITE_DONE);

    if (!success) {
        fprintf(stderr, "Failed to insert message: %s\n", sqlite3_errmsg(db));
    }

    // Cleanup
    sqlite3_finalize(stmt);
    EVP_PKEY_free(sender_priv);
    EVP_PKEY_free(recipient_pub);
    free(packaged.data);
    free(encoded);

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
        "SELECT sender_id, message FROM messages "
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

    // Load our private key
    EVP_PKEY *self_priv = load_private_key_from_pem("keys/self/self_priv.pem");

    // Load contact's public key
    EVP_PKEY *contact_pub = NULL;
    sqlite3_stmt *stmt_pub;
    const char *sql_pub = "SELECT pubkey FROM contacts WHERE id = ?;";

    if (sqlite3_prepare_v2(db, sql_pub, -1, &stmt_pub, NULL) == SQLITE_OK) {
        sqlite3_bind_int(stmt_pub, 1, (self_id == contact_id) ? self_id : contact_id);
        if (sqlite3_step(stmt_pub) == SQLITE_ROW) {
            const char *pubkey_path = (const char *)sqlite3_column_text(stmt_pub, 0);
            contact_pub = load_public_key_from_pem(pubkey_path);
        }
        sqlite3_finalize(stmt_pub);
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        int sender_id = sqlite3_column_int(stmt, 0);
        const char *enc_msg_b64 = (const char *)sqlite3_column_text(stmt, 1);

        // Base64 decode
        size_t bin_len = 0;
        unsigned char *bin_data = base64_decode(enc_msg_b64, &bin_len);
        if (!bin_data) continue;

        SecureMessage msg = {
            .data = bin_data,
            .length = bin_len
        };

        unsigned char *plaintext = NULL;
        size_t plaintext_len = 0;

        EVP_PKEY *sender_key = (sender_id == self_id) ? self_priv : contact_pub;
        EVP_PKEY *receiver_key = (sender_id == self_id) ? contact_pub : self_priv;

        const char *sender_label = (sender_id == self_id) ? "You" : "Them";

        if (parse_and_decrypt_secure_message(&msg, receiver_key, sender_key, &plaintext, &plaintext_len)) {
            char *msg_str = g_strndup((const char *)plaintext, plaintext_len);
            append_message(buffer, sender_label, msg_str);
            g_free(msg_str);
            free(plaintext);
        } else {
            append_message(buffer, sender_label, "[decryption failed]");
        }

        free(bin_data);
    }

    EVP_PKEY_free(self_priv);
    if (contact_pub) EVP_PKEY_free(contact_pub);

    sqlite3_finalize(stmt);
}
