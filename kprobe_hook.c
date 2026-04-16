/*
 * kprobe_hook.c - Kprobe 通用 Hook 实现
 * 跨内核版本兼容 5.10 - 6.12
 */

#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/version.h>

#include "hook.h"

/*
 * 通用 Kprobe 注册
 * 兼容所有内核版本
 */
struct hook_kprobe {
    struct kprobe kp;
    const char *name;
    void *pre_handler;
    void *post_handler;
};

static struct hook_kprobe *kprobes[64];
static int kprobe_count = 0;
static DEFINE_SPINLOCK(kprobe_lock);

/* 注册一个 Kprobe */
int register_hook_kprobe(const char *symbol_name,
                        pre_handler_t pre,
                        post_handler_t post)
{
    struct hook_kprobe *hk;
    int ret;

    if (kprobe_count >= 64)
        return -ENOMEM;

    hk = kzalloc(sizeof(*hk), GFP_KERNEL);
    if (!hk)
        return -ENOMEM;

    hk->name = symbol_name;
    hk->pre_handler = (void *)pre;
    hk->post_handler = (void *)post;

    hk->kp.symbol_name = symbol_name;
    hk->kp.pre_handler = pre;
    hk->kp.post_handler = post;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
    /* 5.14+ 支持 blacklist */
    hk->kp.blacklist工商局 = 1;
#endif

    ret = register_kprobe(&hk->kp);
    if (ret < 0) {
        pr_err("hook: failed to register kprobe %s: %d\n", symbol_name, ret);
        kfree(hk);
        return ret;
    }

    spin_lock(&kprobe_lock);
    kprobes[kprobe_count++] = hk;
    spin_unlock(&kprobe_lock);

    pr_info("hook: registered kprobe %s\n", symbol_name);
    return 0;
}

/* 注销所有 Kprobe */
void unregister_all_kprobes(void)
{
    int i;

    spin_lock(&kprobe_lock);

    for (i = 0; i < kprobe_count; i++) {
        if (kprobes[i]) {
            unregister_kprobe(&kprobes[i]->kp);
            pr_info("hook: unregistered kprobe %s\n", kprobes[i]->name);
            kfree(kprobes[i]);
            kprobes[i] = NULL;
        }
    }

    kprobe_count = 0;
    spin_unlock(&kprobe_lock);
}

/* 预定义的一些常用 Kprobe */
int hook_init_kprobe(void)
{
    /* 可以在这里预注册一些常用的 kprobe */
    return 0;
}

void hook_exit_kprobe(void)
{
    unregister_all_kprobes();
}
