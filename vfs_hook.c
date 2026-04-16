/*
 * vfs_hook.c - VFS getdents64 hook for file hiding
 * ARM64 compatible
 */

#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/fs.h>

#include "hook.h"

MODULE_LICENSE("GPL");

/* Directory entry structure */
struct dirent_entry {
    unsigned long d_ino;
    unsigned long d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[256];
};

/* getdents64 pre_handler - just return 0 to continue */
static int pre_getdents64(struct kprobe *p, struct pt_regs *regs)
{
    return 0;
}

/* Kprobe for sys_getdents64 */
static struct kprobe kp = {
    .symbol_name = "sys_getdents64",
    .pre_handler = pre_getdents64,
};

int vfs_hook_init(void)
{
    int ret;

    ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("hook: failed to register kprobe: %d\n", ret);
        return ret;
    }

    pr_info("hook: getdents64 kprobe registered at %px\n", kp.addr);
    return 0;
}

void vfs_hook_exit(void)
{
    unregister_kprobe(&kp);
    pr_info("hook: getdents64 kprobe unregistered\n");
}
