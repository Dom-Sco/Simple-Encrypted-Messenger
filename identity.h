#ifndef IDENTITY_H
#define IDENTITY_H

#include <gtk/gtk.h>
#include <sqlite3.h>
#include <stddef.h>

int load_username(char *out, size_t out_size);
int prompt_and_save_username();
int get_our_id(sqlite3 *db);

#endif
