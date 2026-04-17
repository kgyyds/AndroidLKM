/*
 * hook_android.c - Android Native eBPF File Hiding Module
 * 
 * 使用 Android bpf() 系统调用直接加载 BPF 程序
 * 无需 libbpf 依赖
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <linux/bpf.h>
#include <asm/unistd.h>

/* BPF map definitions */
#define HIDDEN_FILES_MAX 64
#define HIDDEN_FILES_SIZE 256

/* hidden_files map */
struct bpf_map_def {
    __u32 type;
    __u32 key_size;
    __u32 value_size;
    __u32 max_entries;
    __u32 map_flags;
};

/* BPF program - same logic as hook.bpf.c but in userspace for demonstration */
/* Actual BPF program should be pre-compiled and embedded */

static int running = 1;
static int bpf_fd = -1;
static int hidden_map_fd = -1;
static int rb_fd = -1;

/* eBPF syscall wrapper */
static int bpf(int cmd, union bpf_attr *attr, unsigned int size)
{
    return syscall(__NR_bpf, cmd, attr, size);
}

/* Create BPF map */
static int create_hidden_map(void)
{
    union bpf_attr attr = {
        .map_type = BPF_MAP_TYPE_HASH,
        .key_size = HIDDEN_FILES_SIZE,
        .value_size = sizeof(__u32),
        .max_entries = HIDDEN_FILES_MAX,
        .map_flags = 0,
    };
    
    hidden_map_fd = bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
    if (hidden_map_fd < 0) {
        perror("bpf(BPF_MAP_CREATE) failed");
        return -1;
    }
    
    printf("[hook] Created hidden_files map: fd=%d\n", hidden_map_fd);
    return 0;
}

/* Add file to hidden list */
static int add_hidden_file(const char *name, bool is_dir)
{
    __u32 value = is_dir ? 2 : 1;
    
    if (hidden_map_fd < 0) {
        fprintf(stderr, "[hook] Map not initialized\n");
        return -1;
    }
    
    union bpf_attr attr = {
        .map_fd = hidden_map_fd,
        .key = (__u64)(unsigned long)name,
        .value = (__u64)(unsigned long)&value,
        .flags = BPF_ANY,
    };
    
    int ret = bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
    if (ret < 0) {
        perror("bpf(BPF_MAP_UPDATE_ELEM) failed");
        return ret;
    }
    
    printf("[hook] Added hidden %s: %s\n", is_dir ? "dir" : "file", name);
    return 0;
}

/* Remove file from hidden list */
static int remove_hidden_file(const char *name)
{
    if (hidden_map_fd < 0)
        return -1;
    
    union bpf_attr attr = {
        .map_fd = hidden_map_fd,
        .key = (__u64)(unsigned long)name,
    };
    
    int ret = bpf(BPF_MAP_DELETE_ELEM, &attr, sizeof(attr));
    if (ret < 0 && errno != ENOENT) {
        perror("bpf(BPF_MAP_DELETE_ELEM) failed");
        return ret;
    }
    
    printf("[hook] Removed: %s\n", name);
    return 0;
}

/* List hidden files */
static void list_hidden_files(void)
{
    char key[HIDDEN_FILES_SIZE] = {};
    char next_key[HIDDEN_FILES_SIZE];
    
    printf("[hook] === Hidden Files ===\n");
    
    int count = 0;
    while (bpf(BPF_MAP_GET_NEXT_KEY, &(union bpf_attr){
        .map_fd = hidden_map_fd,
        .key = (__u64)(unsigned long)key,
        .next_key = (__u64)(unsigned long)next_key,
    }, sizeof(union bpf_attr)) == 0) {
        __u32 val;
        memcpy(key, next_key, HIDDEN_FILES_SIZE);
        
        bpf(BPF_MAP_LOOKUP_ELEM, &(union bpf_attr){
            .map_fd = hidden_map_fd,
            .key = (__u64)(unsigned long)key,
            .value = (__u64)(unsigned long)&val,
        }, sizeof(union bpf_attr));
        
        printf("[hook]   %s (%s)\n", key, val == 2 ? "dir" : "file");
        count++;
    }
    
    if (count == 0)
        printf("[hook]   (empty)\n");
}

/* Clear all hidden files */
static void clear_hidden_list(void)
{
    char key[HIDDEN_FILES_SIZE] = {};
    
    while (bpf(BPF_MAP_GET_NEXT_KEY, &(union bpf_attr){
        .map_fd = hidden_map_fd,
        .key = (__u64)(unsigned long)key,
        .next_key = (__u64)(unsigned long)key,
    }, sizeof(union bpf_attr)) == 0) {
        bpf(BPF_MAP_DELETE_ELEM, &(union bpf_attr){
            .map_fd = hidden_map_fd,
            .key = (__u64)(unsigned long)key,
        }, sizeof(union bpf_attr));
    }
    
    printf("[hook] Hidden list cleared\n");
}

/* Print usage */
static void print_usage(const char *prog)
{
    printf("Usage: %s [options]\n", prog);
    printf("Options:\n");
    printf("  add <file>       Add file to hidden list\n");
    printf("  add-d <dir>     Add directory to hidden list\n");
    printf("  remove <name>   Remove from hidden list\n");
    printf("  list             List hidden files\n");
    printf("  clear            Clear all hidden files\n");
    printf("  -h, --help       Show this help\n");
}

static void sig_handler(int sig)
{
    running = 0;
}

int main(int argc, char **argv)
{
    printf("[hook] Android eBPF File Hiding Module v1.0\n");
    printf("[hook] Built for Android ARM64\n\n");
    
    /* Check capabilities */
    if (geteuid() != 0) {
        fprintf(stderr, "[hook] Warning: Not running as root, BPF may fail\n");
    }
    
    /* Set up signal handlers */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGPIPE, SIG_IGN);
    
    /* Create hidden files map */
    if (create_hidden_map() < 0) {
        fprintf(stderr, "[hook] Failed to create BPF map\n");
        return 1;
    }
    
    /* Interactive mode if no args */
    if (argc < 2) {
        printf("[hook] Interactive mode. Type 'help' for commands.\n");
        
        char line[512];
        while (running && fgets(line, sizeof(line), stdin)) {
            /* Parse command */
            char cmd[64] = {}, arg[256] = {};
            sscanf(line, "%s %s", cmd, arg);
            
            if (strcmp(cmd, "add") == 0 && arg[0]) {
                add_hidden_file(arg, false);
            } else if (strcmp(cmd, "add-d") == 0 && arg[0]) {
                add_hidden_file(arg, true);
            } else if (strcmp(cmd, "remove") == 0 && arg[0]) {
                remove_hidden_file(arg);
            } else if (strcmp(cmd, "list") == 0) {
                list_hidden_files();
            } else if (strcmp(cmd, "clear") == 0) {
                clear_hidden_list();
            } else if (strcmp(cmd, "help") == 0 || strcmp(cmd, "?") == 0) {
                print_usage(argv[0]);
            } else if (cmd[0]) {
                fprintf(stderr, "[hook] Unknown command: %s\n", cmd);
            }
            
            memset(line, 0, sizeof(line));
            memset(cmd, 0, sizeof(cmd));
            memset(arg, 0, sizeof(arg));
        }
    } else {
        /* Command line mode */
        if (strcmp(argv[1], "add") == 0 && argc > 2) {
            return add_hidden_file(argv[2], false);
        } else if (strcmp(argv[1], "add-d") == 0 && argc > 2) {
            return add_hidden_file(argv[2], true);
        } else if (strcmp(argv[1], "remove") == 0 && argc > 2) {
            return remove_hidden_file(argv[2]);
        } else if (strcmp(argv[1], "list") == 0) {
            list_hidden_files();
        } else if (strcmp(argv[1], "clear") == 0) {
            clear_hidden_list();
        } else {
            print_usage(argv[0]);
        }
    }
    
    /* Cleanup */
    if (hidden_map_fd >= 0)
        close(hidden_map_fd);
    
    printf("[hook] Exiting\n");
    return 0;
}
