/*
 * hook.h - File hiding module header
 */

#ifndef _HOOK_H
#define _HOOK_H

#include <linux/types.h>

#define MAX_HIDDEN_FILES 64

struct hidden_entry {
	char name[256];
	bool is_dir;
	bool active;
};

int add_hidden_file(const char *name, bool is_dir);
int remove_hidden_file(const char *name);
bool is_hidden(const char *name, bool is_dir);
void clear_hidden_list(void);

#endif
