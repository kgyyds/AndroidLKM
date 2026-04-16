/*
 * hook.h - 文件隐藏模块头文件
 * 用于隐藏文件/目录
 */

#ifndef _HOOK_H
#define _HOOK_H

#include <linux/types.h>
#include <linux/uidgid.h>

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
