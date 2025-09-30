/*
 * contacts_gui.c
 *
 * Build:
 *   gcc contacts_gui.c -o contacts_gui `pkg-config --cflags --libs gtk+-3.0` -lsqlite3
 *
 * Run:
 *   ./contacts_gui
 *
 * Notes:
 * - Requires GTK+3 development packages and sqlite3.
 * - This is a minimal contacts GUI. No networking or encryption yet.
 */

#include <gtk/gtk.h>
#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>
#include "messaging.h"
#include "networking.h"

#define DB_FILE "contacts.db"

#include <glib.h> // for GHashTable

// Maps contact_id (GINT_TO_POINTER) => GtkTextBuffer*
static GHashTable *open_windows = NULL;

extern GHashTable *messaging_windows;  // contact_id → MessagingWindowData*
extern void append_message(GtkTextBuffer *buffer, const char *sender, const char *message); // here

// This is the function that GTK will call on the main thread
gboolean notify_incoming_message(gpointer data) {
    NotifyMessageData *msg = (NotifyMessageData *)data;

    if (!msg) return FALSE;

    // Use sender_id here, not receiver_id
    MessagingWindowData *window_data = g_hash_table_lookup(open_windows, GINT_TO_POINTER(msg->sender_id));

    if (window_data && window_data->history_buffer) {
        append_message(window_data->history_buffer, "Them", msg->message);
    } else {
        g_print("[notify] No open window for contact %d\n", msg->sender_id);
    }

    g_free(msg->message);
    g_free(msg);

    return FALSE;
}



/* Columns for the liststore */
enum {
    COL_ID = 0,
    COL_NAME,
    COL_IP,
    COL_PUBKEY,
    N_COLS
};

typedef struct {
    GtkWidget *window;
    GtkWidget *treeview;
    GtkListStore *liststore;
    sqlite3 *db;
    int self_id;
} AppWidgets;

/* Data passed to send message callback */
typedef struct {
    GtkWidget *entry;
    GtkTextBuffer *history_buffer;
    int contact_id;
    sqlite3 *db;
    int self_id;
} SendMsgData;

/* Function prototypes */
static gboolean get_selected_contact(AppWidgets *app, int *out_id, char **out_name, char **out_ip, char **out_pubkey);
static void open_messaging_window(AppWidgets *app, int contact_id);

/* Utility: show message dialog */
static void show_message(GtkWindow *parent, GtkMessageType type, const char *title, const char *msg) {
    GtkWidget *d = gtk_message_dialog_new(parent, GTK_DIALOG_DESTROY_WITH_PARENT, type,
                                          GTK_BUTTONS_CLOSE, "%s", msg);
    gtk_window_set_title(GTK_WINDOW(d), title);
    gtk_dialog_run(GTK_DIALOG(d));
    gtk_widget_destroy(d);
}

/* Initialize SQLite DB: create table if not exists */
static int init_db(sqlite3 **out_db) {
    sqlite3 *db;
    int rc = sqlite3_open(DB_FILE, &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Can't open DB: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return rc;
    }

    const char *create_sql =
        "CREATE TABLE IF NOT EXISTS contacts ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "name TEXT NOT NULL,"
        "ip TEXT NOT NULL,"
        "pubkey TEXT NOT NULL"
        ");";

    char *err = NULL;
    rc = sqlite3_exec(db, create_sql, 0, 0, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err ? err : "(unknown)");
        sqlite3_free(err);
        sqlite3_close(db);
        return rc;
    }

    *out_db = db;
    return SQLITE_OK;
}

/* Load contacts from DB into liststore */
static void load_contacts(AppWidgets *app) {
    gtk_list_store_clear(app->liststore);

    const char *sql = "SELECT id, name, ip, pubkey FROM contacts ORDER BY name COLLATE NOCASE;";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(app->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare select: %s\n", sqlite3_errmsg(app->db));
        return;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        gint id = sqlite3_column_int(stmt, 0);
        const char *name = (const char *)sqlite3_column_text(stmt, 1);
        const char *ip = (const char *)sqlite3_column_text(stmt, 2);
        const char *pubkey = (const char *)sqlite3_column_text(stmt, 3);

        GtkTreeIter iter;
        gtk_list_store_append(app->liststore, &iter);
        gtk_list_store_set(app->liststore, &iter,
                           COL_ID, id,
                           COL_NAME, name ? name : "",
                           COL_IP, ip ? ip : "",
                           COL_PUBKEY, pubkey ? pubkey : "",
                           -1);
    }

    sqlite3_finalize(stmt);
}

/* Insert contact */
static gboolean insert_contact(AppWidgets *app, const char *name, const char *ip, const char *pubkey, int *out_id) {
    const char *sql = "INSERT INTO contacts (name, ip, pubkey) VALUES (?, ?, ?);";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(app->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return FALSE;
    }

    sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, ip, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, pubkey, -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return FALSE;
    }

    if (out_id) *out_id = (int)sqlite3_last_insert_rowid(app->db);

    sqlite3_finalize(stmt);
    return TRUE;
}

/* Update contact by id */
static gboolean update_contact(AppWidgets *app, int id, const char *name, const char *ip, const char *pubkey) {
    const char *sql = "UPDATE contacts SET name = ?, ip = ?, pubkey = ? WHERE id = ?;";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(app->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return FALSE;
    }

    sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, ip, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, pubkey, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 4, id);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

/* Delete contact */
static gboolean delete_contact(AppWidgets *app, int id) {
    const char *sql = "DELETE FROM contacts WHERE id = ?;";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(app->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return FALSE;
    }

    sqlite3_bind_int(stmt, 1, id);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

/* Get selected contact id and optionally values */
static gboolean get_selected_contact(AppWidgets *app, int *out_id, char **out_name, char **out_ip, char **out_pubkey) {
    GtkTreeSelection *sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(app->treeview));
    GtkTreeModel *model;
    GtkTreeIter iter;
    if (gtk_tree_selection_get_selected(sel, &model, &iter)) {
        int id;
        char *name, *ip, *pubkey;
        gtk_tree_model_get(model, &iter,
                           COL_ID, &id,
                           COL_NAME, &name,
                           COL_IP, &ip,
                           COL_PUBKEY, &pubkey,
                           -1);
        if (out_id) *out_id = id;
        if (out_name) *out_name = name; else g_free(name);
        if (out_ip) *out_ip = ip; else g_free(ip);
        if (out_pubkey) *out_pubkey = pubkey; else g_free(pubkey);
        return TRUE;
    }
    return FALSE;
}

/* Dialog for Add/Edit contact. If edit_id >= 0 then it's edit mode. */
static void show_contact_dialog(AppWidgets *app, int edit_id) {
    GtkWidget *dialog = gtk_dialog_new_with_buttons(edit_id >= 0 ? "Edit Contact" : "Add Contact",
                                                    GTK_WINDOW(app->window),
                                                    GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
                                                    ("_Cancel"), GTK_RESPONSE_CANCEL,
                                                    ("_Save"), GTK_RESPONSE_OK,
                                                    NULL);

    gtk_window_set_default_size(GTK_WINDOW(dialog), 480, -1);
    gtk_window_set_resizable(GTK_WINDOW(dialog), TRUE);

    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dialog));

    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 8);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 8);
    gtk_container_set_border_width(GTK_CONTAINER(grid), 12);
    gtk_container_add(GTK_CONTAINER(content), grid);

    // Name input
    GtkWidget *name_label = gtk_label_new("Name:");
    gtk_widget_set_halign(name_label, GTK_ALIGN_START);
    GtkWidget *name_entry = gtk_entry_new();

    // IP Address input
    GtkWidget *ip_label = gtk_label_new("IP Address:");
    gtk_widget_set_halign(ip_label, GTK_ALIGN_START);
    GtkWidget *ip_entry = gtk_entry_new();

    // Public Key input label
    GtkWidget *pubkey_label = gtk_label_new("Public Key:");
    gtk_widget_set_halign(pubkey_label, GTK_ALIGN_START);
    GtkWidget *pubkey_view = gtk_text_view_new();
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(pubkey_view), GTK_WRAP_WORD_CHAR);
    GtkTextBuffer *pubkey_buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(pubkey_view));
    gtk_widget_set_size_request(pubkey_view, 400, 100);

    gtk_grid_attach(GTK_GRID(grid), name_label, 0, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), name_entry, 1, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), ip_label, 0, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), ip_entry, 1, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), pubkey_label, 0, 2, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), pubkey_view, 1, 2, 1, 1);

    // If edit mode, load current data
    if (edit_id >= 0) {
        const char *sql = "SELECT name, ip, pubkey FROM contacts WHERE id = ?;";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(app->db, sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_int(stmt, 1, edit_id);
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                const char *name = (const char *)sqlite3_column_text(stmt, 0);
                const char *ip = (const char *)sqlite3_column_text(stmt, 1);
                const char *pubkey = (const char *)sqlite3_column_text(stmt, 2);

                gtk_entry_set_text(GTK_ENTRY(name_entry), name ? name : "");
                gtk_entry_set_text(GTK_ENTRY(ip_entry), ip ? ip : "");
                gtk_text_buffer_set_text(pubkey_buffer, pubkey ? pubkey : "", -1);
            }
            sqlite3_finalize(stmt);
        }
    }

    gtk_widget_show_all(dialog);

    int response = gtk_dialog_run(GTK_DIALOG(dialog));
    if (response == GTK_RESPONSE_OK) {
        const char *name = gtk_entry_get_text(GTK_ENTRY(name_entry));
        const char *ip = gtk_entry_get_text(GTK_ENTRY(ip_entry));

        GtkTextIter start, end;
        gtk_text_buffer_get_start_iter(pubkey_buffer, &start);
        gtk_text_buffer_get_end_iter(pubkey_buffer, &end);
        char *pubkey = gtk_text_buffer_get_text(pubkey_buffer, &start, &end, FALSE);

        if (strlen(name) == 0 || strlen(ip) == 0 || strlen(pubkey) == 0) {
            show_message(GTK_WINDOW(dialog), GTK_MESSAGE_WARNING, "Invalid Data", "All fields must be filled.");
        } else {
            gboolean success = FALSE;
            if (edit_id >= 0) {
                success = update_contact(app, edit_id, name, ip, pubkey);
            } else {
                success = insert_contact(app, name, ip, pubkey, NULL);
            }
            if (!success) {
                show_message(GTK_WINDOW(dialog), GTK_MESSAGE_ERROR, "Database Error", "Failed to save contact.");
            } else {
                load_contacts(app);
            }
        }
        g_free(pubkey);
    }

    gtk_widget_destroy(dialog);
}

/* Add Contact button clicked */
static void on_add_contact_clicked(GtkButton *btn, gpointer user_data) {
    AppWidgets *app = (AppWidgets *)user_data;
    show_contact_dialog(app, -1);
}

/* Edit Contact button clicked */
static void on_edit_contact_clicked(GtkButton *btn, gpointer user_data) {
    AppWidgets *app = (AppWidgets *)user_data;
    int id;
    if (get_selected_contact(app, &id, NULL, NULL, NULL)) {
        show_contact_dialog(app, id);
    } else {
        show_message(GTK_WINDOW(app->window), GTK_MESSAGE_INFO, "Edit Contact", "Please select a contact first.");
    }
}

/* Delete Contact button clicked */
static void on_delete_contact_clicked(GtkButton *btn, gpointer user_data) {
    AppWidgets *app = (AppWidgets *)user_data;
    int id;
    char *name = NULL;
    if (get_selected_contact(app, &id, &name, NULL, NULL)) {
        char confirm_msg[256];
        snprintf(confirm_msg, sizeof(confirm_msg), "Delete contact '%s'?", name);
        g_free(name);

        GtkWidget *dialog = gtk_message_dialog_new(GTK_WINDOW(app->window),
                                                   GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
                                                   GTK_MESSAGE_QUESTION,
                                                   GTK_BUTTONS_YES_NO,
                                                   "%s", confirm_msg);
        int response = gtk_dialog_run(GTK_DIALOG(dialog));
        gtk_widget_destroy(dialog);

        if (response == GTK_RESPONSE_YES) {
            if (!delete_contact(app, id)) {
                show_message(GTK_WINDOW(app->window), GTK_MESSAGE_ERROR, "Delete Failed", "Failed to delete contact.");
            } else {
                load_contacts(app);
            }
        }
    } else {
        show_message(GTK_WINDOW(app->window), GTK_MESSAGE_INFO, "Delete Contact", "Please select a contact first.");
    }
}

/* Send button clicked inside messaging window */
static void on_send_button_clicked(GtkButton *btn, gpointer user_data) {
    SendMsgData *data = (SendMsgData *)user_data;
    const char *msg_text = gtk_entry_get_text(GTK_ENTRY(data->entry));

    if (strlen(msg_text) == 0) {
        return; // Ignore empty messages
    }

    // Append message to history buffer (local echo)
    GtkTextIter end_iter;
    gtk_text_buffer_get_end_iter(data->history_buffer, &end_iter);
    gtk_text_buffer_insert(data->history_buffer, &end_iter, "You: ", -1);
    gtk_text_buffer_insert(data->history_buffer, &end_iter, msg_text, -1);
    gtk_text_buffer_insert(data->history_buffer, &end_iter, "\n", -1);

    // Save message to message DB (your implementation)
    send_message(data->db, data->self_id, data->contact_id, msg_text); // Save locally

    // First, look up the recipient IP from the DB
    char *recipient_ip = NULL;
    const char *sql = "SELECT ip FROM contacts WHERE id = ?;";
    sqlite3_stmt *stmt;

    if (sqlite3_prepare_v2(data->db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_int(stmt, 1, data->contact_id);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const unsigned char *ip = sqlite3_column_text(stmt, 0);
            recipient_ip = g_strdup((const char *)ip);
        }
        sqlite3_finalize(stmt);
    }

    if (recipient_ip) {
        // Pass sender_id (self_id) and receiver_id (contact_id) now
        send_message_over_network(recipient_ip, msg_text, data->self_id, data->contact_id);
        g_free(recipient_ip);
    }

    // Clear entry
    gtk_entry_set_text(GTK_ENTRY(data->entry), "");
}


/* Free SendMsgData when messaging window destroyed */
static void on_messaging_window_destroy(GtkWidget *widget, gpointer user_data) {
    MessagingWindowData *window_data = (MessagingWindowData *)user_data;
    if (!window_data) return;

    if (open_windows) {
        g_hash_table_remove(open_windows, GINT_TO_POINTER(window_data->contact_id));
    }

    g_free(window_data);
}

static void open_messaging_window(AppWidgets *app, int contact_id) {
    // Don't open window for self
    if (contact_id == app->self_id) {
        g_print("Not opening messaging window for self (contact_id = %d)\n", contact_id);
        return;
    }

    // Check if window already open, focus it if so
    if (open_windows) {
        MessagingWindowData *existing = g_hash_table_lookup(open_windows, GINT_TO_POINTER(contact_id));
        if (existing) {
            gtk_window_present(GTK_WINDOW(existing->window));
            return;
        }
    } else {
        open_windows = g_hash_table_new(g_direct_hash, g_direct_equal);
    }

    // Get contact name for window title
    char *name = NULL;
    {
        const char *sql = "SELECT name FROM contacts WHERE id = ?;";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(app->db, sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_int(stmt, 1, contact_id);
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                const unsigned char *n = sqlite3_column_text(stmt, 0);
                if (n) name = g_strdup((const char *)n);
            }
            sqlite3_finalize(stmt);
        }
    }
    if (!name) {
        name = g_strdup("Unknown");
    }

    GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), g_strdup_printf("Messaging: %s", name));
    gtk_window_set_default_size(GTK_WINDOW(window), 500, 400);
    gtk_window_set_transient_for(GTK_WINDOW(window), GTK_WINDOW(app->window));
    gtk_window_set_modal(GTK_WINDOW(window), TRUE);

    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_container_add(GTK_CONTAINER(window), vbox);

    // Message history (read-only textview)
    GtkWidget *history_view = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(history_view), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(history_view), FALSE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(history_view), GTK_WRAP_WORD_CHAR);

    GtkTextBuffer *history_buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(history_view));
    gtk_box_pack_start(GTK_BOX(vbox), history_view, TRUE, TRUE, 0);

    // Load message history
    load_message_history(app->db, app->self_id, contact_id, history_buffer);

    // Entry + Send button box
    GtkWidget *hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 0);

    GtkWidget *entry = gtk_entry_new();
    gtk_box_pack_start(GTK_BOX(hbox), entry, TRUE, TRUE, 0);

    GtkWidget *send_btn = gtk_button_new_with_label("Send");
    gtk_box_pack_start(GTK_BOX(hbox), send_btn, FALSE, FALSE, 0);

    // Setup SendMsgData for callback
    SendMsgData *send_data = g_new0(SendMsgData, 1);
    send_data->entry = entry;
    send_data->history_buffer = history_buffer;
    send_data->contact_id = contact_id;
    send_data->self_id = app->self_id;
    send_data->db = app->db;

    g_signal_connect(send_btn, "clicked", G_CALLBACK(on_send_button_clicked), send_data);

    // Allocate MessagingWindowData and store in hash table
    MessagingWindowData *window_data = g_new0(MessagingWindowData, 1);
    window_data->contact_id = contact_id;
    window_data->window = window;
    window_data->history_buffer = history_buffer;
    window_data->entry = entry;

    g_hash_table_insert(open_windows, GINT_TO_POINTER(contact_id), window_data);

    // Connect destroy to free resources
    g_signal_connect(window, "destroy", G_CALLBACK(on_messaging_window_destroy), window_data);

    gtk_widget_show_all(window);
    g_free(name);
}

/* Message Contact button clicked */
static void on_message_contact(GtkButton *btn, gpointer user_data) {
    AppWidgets *app = (AppWidgets *)user_data;
    int id;
    if (get_selected_contact(app, &id, NULL, NULL, NULL)) {
        open_messaging_window(app, id);
    } else {
        show_message(GTK_WINDOW(app->window), GTK_MESSAGE_INFO, "Message Contact", "Please select a contact first.");
    }
}

/* Create and set up tree view with columns */
static GtkWidget *create_tree_view(AppWidgets *app) {
    GtkListStore *store = gtk_list_store_new(N_COLS, G_TYPE_INT, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);
    app->liststore = store;

    GtkWidget *view = gtk_tree_view_new_with_model(GTK_TREE_MODEL(store));

    GtkCellRenderer *renderer;
    GtkTreeViewColumn *col;

    // Name column
    renderer = gtk_cell_renderer_text_new();
    col = gtk_tree_view_column_new_with_attributes("Name", renderer, "text", COL_NAME, NULL);
    gtk_tree_view_append_column(GTK_TREE_VIEW(view), col);

    // IP Address column
    renderer = gtk_cell_renderer_text_new();
    col = gtk_tree_view_column_new_with_attributes("IP Address", renderer, "text", COL_IP, NULL);
    gtk_tree_view_append_column(GTK_TREE_VIEW(view), col);

    // Public Key column (show truncated)
    renderer = gtk_cell_renderer_text_new();
    col = gtk_tree_view_column_new_with_attributes("Public Key", renderer, "text", COL_PUBKEY, NULL);
    gtk_tree_view_append_column(GTK_TREE_VIEW(view), col);

    return view;
}

/* Create main application window */
static void create_main_window(AppWidgets *app) {
    app->window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(app->window), "Contacts");
    gtk_window_set_default_size(GTK_WINDOW(app->window), 800, 400);
    g_signal_connect(app->window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_container_add(GTK_CONTAINER(app->window), vbox);

    app->treeview = create_tree_view(app);
    gtk_box_pack_start(GTK_BOX(vbox), app->treeview, TRUE, TRUE, 0);

    // Buttons box
    GtkWidget *hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_box_set_homogeneous(GTK_BOX(hbox), FALSE);
    gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 6);

    GtkWidget *btn_add = gtk_button_new_with_label("Add");
    GtkWidget *btn_edit = gtk_button_new_with_label("Edit");
    GtkWidget *btn_delete = gtk_button_new_with_label("Delete");
    GtkWidget *btn_message = gtk_button_new_with_label("Message");

    // Pack Add/Edit/Delete on left
    gtk_box_pack_start(GTK_BOX(hbox), btn_add, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(hbox), btn_edit, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(hbox), btn_delete, FALSE, FALSE, 0);

    // Pack Message on right
    GtkWidget *hbox_spacer = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_widget_set_hexpand(hbox_spacer, TRUE);
    gtk_box_pack_start(GTK_BOX(hbox), hbox_spacer, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(hbox), btn_message, FALSE, FALSE, 0);

    g_signal_connect(btn_add, "clicked", G_CALLBACK(on_add_contact_clicked), app);
    g_signal_connect(btn_edit, "clicked", G_CALLBACK(on_edit_contact_clicked), app);
    g_signal_connect(btn_delete, "clicked", G_CALLBACK(on_delete_contact_clicked), app);
    g_signal_connect(btn_message, "clicked", G_CALLBACK(on_message_contact), app);
}

int get_self_id(sqlite3 *db, const char *self_name) {
    const char *sql = "SELECT id FROM contacts WHERE name = ?;";
    sqlite3_stmt *stmt;
    int self_id = -1;  // Default if not found

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, self_name, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            self_id = sqlite3_column_int(stmt, 0);
        }
        sqlite3_finalize(stmt);
    } else {
        fprintf(stderr, "Failed to prepare self_id lookup: %s\n", sqlite3_errmsg(db));
    }

    return self_id;
}

/* Main function */
int main(int argc, char *argv[]) {
    gtk_init(&argc, &argv);

    AppWidgets app;
    memset(&app, 0, sizeof(AppWidgets));  // Zero before use

    // Initialize SQLite
    if (init_db(&app.db) != SQLITE_OK) {
        fprintf(stderr, "❌ Failed to initialize database.\n");
        return 1;
    }

    // Create messages table
    if (init_message_db(app.db) != SQLITE_OK) {
        fprintf(stderr, "❌ Failed to initialize messaging database.\n");
        sqlite3_close(app.db);
        return 1;
    }

    // Set your self name (can be loaded from config, input, etc.)
    const char *self_name = "Barney";  // Replace with actual self-name or make configurable

    // Get self ID
    app.self_id = get_self_id(app.db, self_name);

    // Start background server thread
    start_message_server(app.db);

    // Create hash table for managing open chat windows
    messaging_windows = g_hash_table_new(g_direct_hash, g_direct_equal);

    // GUI setup
    create_main_window(&app);
    load_contacts(&app);

    gtk_widget_show_all(app.window);
    gtk_main();

    sqlite3_close(app.db);
    return 0;
}


