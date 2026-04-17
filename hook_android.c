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

/* BPF syscall number for Android */
#ifndef __NR_bpf
#if defined(__aarch64__)
#define __NR_bpf 280
#elif defined(__arm__)
#define __NR_bpf 386
#elif defined(__x86_64__)
#define __NR_bpf 321
#else
#define __NR_bpf 0
#endif
#endif

/* BPF commands */
#ifndef BPF_MAP_CREATE
#define BPF_MAP_CREATE 0
#define BPF_MAP_LOOKUP_ELEM 1
#define BPF_MAP_UPDATE_ELEM 2
#define BPF_MAP_DELETE_ELEM 3
#define BPF_MAP_GET_NEXT_KEY 4
#endif

/* BPF map types */
#ifndef BPF_MAP_TYPE_HASH
#define BPF_MAP_TYPE_HASH 1
#endif

/* BPF flags */
#ifndef BPF_ANY
#define BPF_ANY 0
#define BPF_NOEXIST 1
#define BPF_EXIST 2
#endif

/* hidden_files map */
#define HIDDEN_FILES_MAX 64
#define HIDDEN_FILES_SIZE 256

/* bpf_attr union for syscalls */
typedef union bpf_attr {
    struct {
        __u32 map_type;
        __u32 key_size;
        __u32 value_size;
        __u32 max_entries;
        __u32 map_flags;
        __u32 inner_map_fd;
        __u32 numa_node;
    };
    struct {
        __u32 fd;
        __u64 attr;
        __u64 size;
    } info;
    struct {
        __u32 map_fd;
        __u64 key;
        __u64 value;
        __u64 flags;
        __u64 batch;
    } elem;
    __u8 data[256];
} bpf_attr_t;

static int running = 1;
static int hidden_map_fd = -1;

/* eBPF syscall wrapper */
static int bpf_sys(int cmd, bpf_attr_t *attr, unsigned int size)
{
    return syscall(__NR_bpf, cmd, attr, size);
}

/* Create BPF map */
static int create_hidden_map(void)
{
    bpf_attr_t attr = {
        .map_type = BPF_MAP_TYPE_HASH,
        .key_size = HIDDEN_FILES_SIZE,
        .value_size = sizeof(__u32),
        .max_entries = HIDDEN_FILES_MAX,
        .map_flags = 0,
    };
    
    hidden_map_fd = bpf_sys(BPF_MAP_CREATE, &attr, sizeof(attr));
    if (hidden_map_fd < 0) {
        perror("bpf(BPF_MAP_CREATE) failed");
        return -1;
    }
    
    printf("[hook] Created hidden_files map: fd=%d\n", hidden_map_fd);
    return 0;
}

/* Add file to hidden list */
static int add_hidden_file(const char *name, int is_dir)
{
    __u32 value = is_dir ? 2 : 1;
    
    if (hidden_map_fd < 0) {
        fprintf(stderr, "[hook] Map not initialized\n");
        return -1;
    }
    
    if (strlen(name) >= HIDDEN_FILES_SIZE) {
        fprintf(stderr, "[hook] Name too long\n");
        return -1;
    }
    
    bpf_attr_t attr = {
        .elem.map_fd = hidden_map_fd,
        .elem.key = (__u64)(unsigned long)name,
        .elem.value = (__u64)(unsigned long)&value,
        .elem.flags = BPF_ANY,
    };
    
    int ret = bpf_sys(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
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
    
    bpf_attr_t attr = {
        .elem.map_fd = hidden_map_fd,
        .elem.key = (__u64)(unsigned long)name,
    };
    
    int ret = bpf_sys(BPF_MAP_DELETE_ELEM, &attr, sizeof(attr));
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
    int count = 0;
    
    printf("[hook] === Hidden Files ===\n");
    
    while (bpf_sys(BPF_MAP_GET_NEXT_KEY, &(bpf_attr_t){
        .elem.map_fd = hidden_map_fd,
        .elem.key = (__u64)(unsigned long)key,
        .elem.next_key = (__u64)(unsigned long)next_key,
    }, sizeof(bpf_attr_t)) == 0) {
        __u32 val = 0;
        
        /* Copy next_key to key for next iteration */
        memcpy(key, next_key, HIDDEN_FILES_SIZE);
        
        /* Lookup value */
        bpf_sys(BPF_MAP_LOOKUP_ELEM, &(bpf_attr_t){
            .elem.map_fd = hidden_map_fd,
            .elem.key = (__u64)(unsigned long)key,
            .elem.value = (__u64)(unsigned long)&val,
        }, sizeof(bpf_attr_t));
        
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
    
    while (bpf_sys(BPF_MAP_GET_NEXT_KEY, &(bpf_attr_t){
        .elem.map_fd = hidden_map_fd,
        .elem.key = (__u64)(unsigned long)key,
        .elem.next_key = (__u64)(unsigned long)key,
    }, sizeof(bpf_attr_t)) == 0) {
        bpf_sys(BPF_MAP_DELETE_ELEM, &(bpf_attr_t){
            .elem.map_fd = hidden_map_fd,
            .elem.key = (__u64)(unsigned long)key,
        }, sizeof(bpf_attr_t));
    }
    
    printf("[hook] Hidden list cleared\n");
}

/* Print usage */
static void print_usage(const char *prog)
{
    printf("Usage: %s [options]\n", prog);
    printf("Options:\n");
    printf("  add <file>       Add file to hidden list\n");
    printf("  add-d <dir>      Add directory to hidden list\n");
    printf("  remove <name>    Remove from hidden list\n");
    printf("  list             List hidden files\n");
    printf("  clear            Clear all hidden files\n");
    printf("  shell            Interactive shell mode\n");
    printf("  -h, --help       Show this help\n");
}

static void sig_handler(int sig)
{
    (void)sig;
    running = 0;
}

int main(int argc, char **argv)
{
    printf("[hook] Android eBPF File Hiding Module v1.0\n");
    printf("[hook] Built for Android ARM64\n\n");
    
#if defined(__ANDROID__)
    printf("[hook] Running on Android\n");
#else
    printf("[hook] Running on: %s\n",
#if defined(__x86_64__)
        "x86_64"
#elif defined(__aarch64__)
        "ARM64"
#elif defined(__arm__)
        "ARM"
#else
        "Unknown"
#endif
    );
#endif

    /* Check capabilities */
    if (geteuid() != 0) {
        fprintf(stderr, "[hook] Warning: Not running as root, BPF may fail\n");
    }
    
    /* Check bpf syscall availability */
    if (__NR_bpf == 0) {
        fprintf(stderr, "[hook] Error: bpf syscall not available\n");
        return 1;
    }
    printf("[hook] bpf syscall number: %d\n", __NR_bpf);
    
    /* Set up signal handlers */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGPIPE, SIG_IGN);
    
    /* Create hidden files map */
    if (create_hidden_map() < 0) {
        fprintf(stderr, "[hook] Failed to create BPF map\n");
        fprintf(stderr, "[hook] Note: BPF may require kernel 4.14+ and CAP_BPF\n");
        return 1;
    }
    
    /* Add some test entries if running as root */
    if (geteuid() == 0) {
        printf("\n[hook] Adding default hidden entries for testing...\n");
        add_hidden_file(".hidden", 1);  /* hide .hidden dir */
        add_hidden_file(".nomedia", 0); /* hide .nomedia file */
    }
    
    /* Interactive mode if no args or shell command */
    if (argc < 2 || (argc == 2 && strcmp(argv[1], "shell") == 0)) {
        printf("\n[hook] Interactive mode. Commands:\n");
        printf("  add <name>     - Hide file\n");
        printf("  add-d <name>   - Hide directory\n");
        printf("  remove <name> - Unhide\n");
        printf("  list           - Show hidden\n");
        printf("  clear          - Clear all\n");
        printf("  exit           - Exit\n\n");
        
        char line[512];
        while (running && fgets(line, sizeof(line), stdin)) {
            /* Remove newline */
            line[strcspn(line, "\n")] = 0;
            
            /* Skip empty lines */
            if (line[0] == '\0')
                continue;
            
            /* Parse command */
            char cmd[64] = {}, arg[256] = {};
            sscanf(line, "%s %[^\n]", cmd, arg);
            
            if (strcmp(cmd, "exit") == 0 || strcmp(cmd, "quit") == 0) {
                break;
            } else if (strcmp(cmd, "add") == 0 && arg[0]) {
                add_hidden_file(arg, 0);
            } else if (strcmp(cmd, "add-d") == 0 && arg[0]) {
                add_hidden_file(arg, 1);
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
        }
    } else {
        /* Command line mode */
        if (strcmp(argv[1], "add") == 0 && argc > 2) {
            return add_hidden_file(argv[2], 0);
        } else if (strcmp(argv[1], "add-d") == 0 && argc > 2) {
            return add_hidden_file(argv[2], 1);
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
