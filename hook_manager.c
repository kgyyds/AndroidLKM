/*
 * hook_manager.c - 最简单的测试模块
 * 排除法：先确认模块能加载，再逐步加功能
 */

#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "hook.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("HOOK");
MODULE_DESCRIPTION("File Hiding Module - Test");
MODULE_VERSION("1.0");

/* Hidden file storage */
static struct hidden_entry hidden_files[MAX_HIDDEN_FILES];
static int hidden_count;
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
		clear_hidden_list();
		kfree(kbuf);
		return count;
	}

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

static int __init hook_init(void)
{
	int ret;

	pr_info("hook: initializing (simple test)...\n");

	ret = misc_register(&hidefile_dev);
	if (ret < 0) {
		pr_err("hook: misc_register failed: %d\n", ret);
		return ret;
	}
	dev_registered = true;

	pr_info("hook: /dev/hidefile created\n");
	pr_info("hook: module initialized (no syscall hook yet)\n");
	return 0;
}

static void __exit hook_exit(void)
{
	if (dev_registered) {
		misc_deregister(&hidefile_dev);
		dev_registered = false;
	}
	clear_hidden_list();
	pr_info("hook: module exited\n");
}

module_init(hook_init);
module_exit(hook_exit);
