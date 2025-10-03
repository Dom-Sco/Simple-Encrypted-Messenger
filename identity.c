#include "identity.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gtk/gtk.h>
#include <sqlite3.h>

#define USERNAME_FILE "keys/self/username.txt"

int load_username(char *out, size_t out_size) {
    FILE *fp = fopen(USERNAME_FILE, "r");
    if (!fp) return -1;

    if (!fgets(out, out_size, fp)) {
        fclose(fp);
        return -1;
    }

    out[strcspn(out, "\n")] = 0; // Remove trailing newline
    fclose(fp);
    return 0;
}

int prompt_and_save_username() {
    char input[128];
    printf("Enter your username: ");
    if (!fgets(input, sizeof(input), stdin)) {
        return -1;
    }

    input[strcspn(input, "\n")] = 0; // Strip newline

    FILE *fp = fopen(USERNAME_FILE, "w");
    if (!fp) return -1;

    fprintf(fp, "%s\n", input);
    fclose(fp);
    return 0;
}

// Optional: Get our own contact ID based on our stored username
int get_our_id(sqlite3 *db) {
    char username[128];
    if (load_username(username, sizeof(username)) != 0) {
        fprintf(stderr, "Failed to load username\n");
        return -1;
    }

    const char *sql = "SELECT id FROM contacts WHERE name = ?";
    sqlite3_stmt *stmt;
    int user_id = -1;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            user_id = sqlite3_column_int(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }

    return user_id;
}

