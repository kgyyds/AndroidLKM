/*
 * hook.h - eBPF File Hiding Module
 * Userspace API header
 */

#ifndef _HOOK_H
#define _HOOK_H

#include <linux/types.h>
#include <stdbool.h>

#define MAX_HIDDEN_FILES 64

/* Add file to hidden list (userspace) */
int add_hidden_file(const char *name, bool is_dir);

/* Remove file from hidden list */
int remove_hidden_file(const char *name);

/* Clear all hidden files */
void clear_hidden_list(void);

#endif
