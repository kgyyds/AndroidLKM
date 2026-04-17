/*
 * hook_android.c - Android Native eBPF File Hiding Module
 * 
 * 直接通过 bpf() syscall 创建 map 并管理隐藏文件列表
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
#include <sys/syscall.h>

/* Log to stdout */
#define LOG(fmt, ...) fprintf(stdout, "[hook] " fmt "\n", ##__VA_ARGS__)
#define LOG_ERR(fmt, ...) fprintf(stderr, "[hook:ERROR] " fmt "\n", ##__VA_ARGS__)

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
#define BPF_MAP_CREATE 0
#define BPF_MAP_LOOKUP_ELEM 1
#define BPF_MAP_UPDATE_ELEM 2
#define BPF_MAP_DELETE_ELEM 3
#define BPF_MAP_GET_NEXT_KEY 4

/* BPF map types */
#define BPF_MAP_TYPE_HASH 1

/* BPF flags */
#define BPF_ANY 0

/* Map definitions */
#define HIDDEN_FILES_MAX 64
#define HIDDEN_FILES_SIZE 256

/* bpf_attr - must match kernel layout exactly */
typedef struct {
    __u32 map_fd;
    __u64 key;
    __u64 value;
    __u64 flags;
    __u64 next_key;
} bpf_elem_attr_t;

typedef struct {
    __u32 map_type;
    __u32 key_size;
    __u32 value_size;
    __u32 max_entries;
    __u32 map_flags;
    __u32 inner_map_fd;
    __u32 numa_node;
} bpf_create_attr_t;

typedef union bpf_attr {
    bpf_create_attr_t create;
    bpf_elem_attr_t elem;
    __u8 data[256];
} bpf_attr_t;

static int running = 1;
static int hidden_map_fd = -1;

/* eBPF syscall wrapper */
static int bpf_sys(int cmd, bpf_attr_t *attr)
{
    int ret = syscall(__NR_bpf, cmd, attr, sizeof(bpf_attr_t));
    return ret;
}

/* Create BPF map */
static int create_hidden_map(void)
{
    LOG("Creating BPF hash map...");
    
    bpf_attr_t attr = {
        .create.map_type = BPF_MAP_TYPE_HASH,
        .create.key_size = HIDDEN_FILES_SIZE,
        .create.value_size = sizeof(__u32),
        .create.max_entries = HIDDEN_FILES_MAX,
        .create.map_flags = 0,
    };
    
    hidden_map_fd = bpf_sys(BPF_MAP_CREATE, &attr);
    if (hidden_map_fd < 0) {
        LOG_ERR("Failed to create map: %d", hidden_map_fd);
        return -1;
    }
    
    LOG("Created hidden_files map: fd=%d", hidden_map_fd);
    return 0;
}

/* Add file to hidden list */
static int add_hidden_file(const char *name, int is_dir)
{
    __u32 value = is_dir ? 2 : 1;
    
    LOG("Adding hidden %s: '%s'", is_dir ? "dir" : "file", name);
    
    if (hidden_map_fd < 0) {
        LOG_ERR("Map not initialized");
        return -1;
    }
    
    if (strlen(name) >= HIDDEN_FILES_SIZE) {
        LOG_ERR("Name too long: %zu", strlen(name));
        return -1;
    }
    
    bpf_attr_t attr = {
        .elem.map_fd = hidden_map_fd,
        .elem.key = (__u64)(unsigned long)name,
        .elem.value = (__u64)(unsigned long)&value,
        .elem.flags = BPF_ANY,
    };
    
    int ret = bpf_sys(BPF_MAP_UPDATE_ELEM, &attr);
    if (ret < 0) {
        LOG_ERR("Failed to add %s: %d", name, ret);
        return ret;
    }
    
    LOG("Added: '%s' (is_dir=%d, value=%u)", name, is_dir, value);
    return 0;
}

/* Remove file from hidden list */
static int remove_hidden_file(const char *name)
{
    LOG("Removing: '%s'", name);
    
    if (hidden_map_fd < 0)
        return -1;
    
    bpf_attr_t attr = {
        .elem.map_fd = hidden_map_fd,
        .elem.key = (__u64)(unsigned long)name,
    };
    
    int ret = bpf_sys(BPF_MAP_DELETE_ELEM, &attr);
    if (ret < 0 && errno != ENOENT) {
        LOG_ERR("Failed to remove %s: %d", name, ret);
        return ret;
    }
    
    LOG("Removed: '%s'", name);
    return 0;
}

/* List hidden files */
static void list_hidden_files(void)
{
    LOG("Listing hidden files...");
    LOG("  map_fd=%d", hidden_map_fd);
    
    char key[HIDDEN_FILES_SIZE] = {};
    char next_key[HIDDEN_FILES_SIZE];
    int count = 0;
    
    while (1) {
        /* First call with empty key to get first key */
        memset(next_key, 0, HIDDEN_FILES_SIZE);
        
        bpf_attr_t attr = {0};
        attr.elem.map_fd = hidden_map_fd;
        attr.elem.key = (__u64)(unsigned long)key;
        attr.elem.next_key = (__u64)(unsigned long)next_key;
        
        LOG("  Calling GET_NEXT_KEY with key='%s'", key);
        
        int ret = bpf_sys(BPF_MAP_GET_NEXT_KEY, &attr);
        if (ret < 0) {
            if (errno == ENOENT) {
                LOG("  No more keys, iteration complete");
                break;
            }
            LOG_ERR("GET_NEXT_KEY failed: ret=%d, errno=%d (%s)", ret, errno, strerror(errno));
            break;
        }
        
        LOG("  GET_NEXT_KEY returned, next_key='%s'", next_key);
        
        /* Check if next_key is valid */
        if (next_key[0] == '\0') {
            LOG("  next_key is empty, stopping");
            break;
        }
        
        /* Copy next_key to key */
        memcpy(key, next_key, HIDDEN_FILES_SIZE);
        
        /* Lookup value */
        __u32 val = 0;
        bpf_attr_t lookup_attr = {0};
        lookup_attr.elem.map_fd = hidden_map_fd;
        lookup_attr.elem.key = (__u64)(unsigned long)key;
        lookup_attr.elem.value = (__u64)(unsigned long)&val;
        
        ret = bpf_sys(BPF_MAP_LOOKUP_ELEM, &lookup_attr);
        if (ret == 0) {
            LOG("  [%d] '%s' (%s)", count, key, val == 2 ? "dir" : "file");
            count++;
        }
    }
    
    if (count == 0) {
        LOG("  (empty)");
    }
}

/* Clear all hidden files */
static void clear_hidden_list(void)
{
    LOG("Clearing all hidden files...");
    
    char key[HIDDEN_FILES_SIZE] = {};
    char next_key[HIDDEN_FILES_SIZE];
    int count = 0;
    
    while (1) {
        memset(next_key, 0, HIDDEN_FILES_SIZE);
        
        bpf_attr_t attr = {0};
        attr.elem.map_fd = hidden_map_fd;
        attr.elem.key = (__u64)(unsigned long)key;
        attr.elem.next_key = (__u64)(unsigned long)next_key;
        
        int ret = bpf_sys(BPF_MAP_GET_NEXT_KEY, &attr);
        if (ret < 0) {
            if (errno == ENOENT)
                break;
            LOG_ERR("GET_NEXT_KEY failed: %d", ret);
            break;
        }
        
        if (next_key[0] == '\0')
            break;
        
        /* Copy next_key to key */
        memcpy(key, next_key, HIDDEN_FILES_SIZE);
        
        /* Delete this key */
        bpf_attr_t del_attr = {0};
        del_attr.elem.map_fd = hidden_map_fd;
        del_attr.elem.key = (__u64)(unsigned long)key;
        
        ret = bpf_sys(BPF_MAP_DELETE_ELEM, &del_attr);
        if (ret >= 0) {
            count++;
        }
    }
    
    LOG("Cleared %d entries", count);
}

/* Print usage */
static void print_usage(const char *prog)
{
    printf("\n=== Android eBPF File Hiding Module ===\n");
    printf("\nUsage: %s <command>\n\n", prog);
    printf("Commands:\n");
    printf("  add <file>       Hide a file\n");
    printf("  add-d <dir>      Hide a directory\n");
    printf("  remove <name>    Remove from hidden list\n");
    printf("  list             List all hidden files\n");
    printf("  clear            Clear all hidden files\n");
    printf("  shell            Interactive shell mode\n");
    printf("  help             Show this help\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s add secret.txt\n", prog);
    printf("  %s add-d hidden_folder\n", prog);
    printf("  %s list\n", prog);
    printf("\n");
}

static void sig_handler(int sig)
{
    (void)sig;
    running = 0;
}

int main(int argc, char **argv)
{
    printf("\n=== Android eBPF File Hiding Module v1.0 ===\n");
    printf("=== Built for Android ARM64 ===\n\n");
    
    printf("[System Info]\n");
    printf("  bpf syscall number: %d\n", __NR_bpf);
    printf("  uid: %d\n", getuid());
    printf("\n");
    
    /* Check bpf syscall availability */
    if (__NR_bpf == 0) {
        LOG_ERR("bpf syscall not available on this platform!");
        return 1;
    }
    
    /* Check capabilities */
    if (geteuid() != 0) {
        printf("[WARNING] Not running as root, BPF may fail\n");
        printf("[WARNING] Most operations require root privileges\n\n");
    }
    
    /* Set up signal handlers */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGPIPE, SIG_IGN);
    
    /* Create hidden files map */
    if (create_hidden_map() < 0) {
        LOG_ERR("Failed to create BPF map!");
        LOG_ERR("Make sure the kernel supports BPF and you have proper permissions");
        return 1;
    }
    
    /* Add some default entries for testing (if root) */
    if (geteuid() == 0) {
        printf("\n[Adding default hidden entries for testing]\n");
        add_hidden_file(".hidden", 1);    /* hide .hidden dir */
        add_hidden_file(".nomedia", 0);   /* hide .nomedia file */
        add_hidden_file("test_file", 0);  /* hide test_file */
        printf("\n");
    }
    
    /* Interactive mode if no args or shell command */
    if (argc < 2 || (argc == 2 && strcmp(argv[1], "shell") == 0)) {
        printf("Entering interactive mode. Type 'help' for commands.\n\n");
        
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
                LOG_ERR("Unknown command: %s", cmd);
            }
            
            memset(line, 0, sizeof(line));
            memset(cmd, 0, sizeof(cmd));
            memset(arg, 0, sizeof(arg));
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
    
    printf("\n[hook] Exiting\n");
    return 0;
}
