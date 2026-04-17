/*
 * hook_android.c - Android Native eBPF File Hiding Module
 * 
 * 直接通过 bpf() syscall 加载 eBPF 程序并管理隐藏文件
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
#include <sys/mman.h>
#include <stdint.h>

/* Log to stdout */
#define LOG(fmt, ...) fprintf(stdout, "[hook] " fmt "\n", ##__VA_ARGS__)
#define LOG_ERR(fmt, ...) fprintf(stderr, "[hook:ERROR] " fmt "\n", ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...) fprintf(stderr, "[hook:DEBUG] " fmt "\n", ##__VA_ARGS__)

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
#define BPF_PROG_LOAD 5
#define BPF_ATTACH 6
#define BPF_LINK_CREATE 27

/* BPF program types */
#define BPF_PROG_TYPE_TRACEPOINT 8

/* BPF attach types */
#define BPF_TRACEPOINT 8

/* BPF map types */
#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_RINGBUF 6

/* BPF flags */
#define BPF_ANY 0
#define BPF_F_RDONLY 4
#define BPF_F_WRONLY 8

/* Map definitions */
#define HIDDEN_FILES_MAX 64
#define HIDDEN_FILES_SIZE 32

/* bpf_attr - must match kernel layout exactly */
typedef struct {
    __u32         map_type;
    __u32         key_size;
    __u32         value_size;
    __u32         max_entries;
    __u32         map_flags;
    __u32         inner_map_fd;
    __u32         numa_node;
} bpf_create_attr_t;

typedef struct {
    __u32         map_fd;
    __u64         key;
    union {
        __u64     value;
        __u64     next_key;
    };
    __u64         flags;
} bpf_elem_attr_t;

typedef struct {
    __u32         prog_type;
    __u32         insn_cnt;
    __u64         insns;
    __u64         license;
    __u32         log_level;
    __u32         log_size;
    __u64         log_buf;
    __u32         kern_version;
    __u32         prog_flags;
    char          fixup_map_hash_1[192];
} bpf_prog_load_attr_t;

static int running = 1;
static int hidden_map_fd = -1;
static int stats_map_fd = -1;
static int rb_map_fd = -1;
static int prog_fd = -1;
static int link_fd = -1;

/* eBPF syscall wrapper */
static int bpf_sys(int cmd, void *attr, int size)
{
    LOG_DEBUG("bpf_sys: cmd=%d, size=%d", cmd, size);
    int ret = syscall(__NR_bpf, cmd, attr, size);
    if (ret < 0) {
        LOG_ERR("bpf cmd %d failed: errno=%d (%s)", cmd, errno, strerror(errno));
    } else {
        LOG_DEBUG("bpf cmd %d succeeded: ret=%d", cmd, ret);
    }
    return ret;
}

/* Create BPF map */
static int create_hidden_map(void)
{
    LOG("Creating BPF hash map...");
    
    bpf_create_attr_t attr = {
        .map_type = BPF_MAP_TYPE_HASH,
        .key_size = HIDDEN_FILES_SIZE,
        .value_size = sizeof(__u32),
        .max_entries = HIDDEN_FILES_MAX,
        .map_flags = 0,
    };
    
    LOG_DEBUG("BPF_MAP_CREATE: type=%d, key_size=%d, value_size=%d, max_entries=%d",
              attr.map_type, attr.key_size, attr.value_size, attr.max_entries);
    
    hidden_map_fd = bpf_sys(BPF_MAP_CREATE, &attr, sizeof(attr));
    if (hidden_map_fd < 0) {
        return -1;
    }
    
    LOG("Created hidden_files map: fd=%d", hidden_map_fd);
    return 0;
}

/* Create stats map */
static int create_stats_map(void)
{
    LOG("Creating stats map...");
    
    bpf_create_attr_t attr = {
        .map_type = BPF_MAP_TYPE_ARRAY,
        .key_size = sizeof(__u32),
        .value_size = sizeof(__u64),
        .max_entries = 4,
        .map_flags = 0,
    };
    
    stats_map_fd = bpf_sys(BPF_MAP_CREATE, &attr, sizeof(attr));
    if (stats_map_fd < 0) {
        return -1;
    }
    
    LOG("Created stats map: fd=%d", stats_map_fd);
    return 0;
}

/* Create ringbuf map */
static int create_rb_map(void)
{
    LOG("Creating ringbuf map...");
    
    bpf_create_attr_t attr = {
        .map_type = BPF_MAP_TYPE_RINGBUF,
        .key_size = 0,
        .value_size = 0,
        .max_entries = 4096 * 2,
        .map_flags = 0,
    };
    
    rb_map_fd = bpf_sys(BPF_MAP_CREATE, &attr, sizeof(attr));
    if (rb_map_fd < 0) {
        return -1;
    }
    
    LOG("Created ringbuf map: fd=%d", rb_map_fd);
    return 0;
}

/* Add file to hidden list */
static int add_hidden_file(const char *name, int is_dir)
{
    __u32 value = is_dir ? 2 : 1;
    
    LOG("Adding hidden %s: '%s' (value=%u)", is_dir ? "dir" : "file", name, value);
    
    if (hidden_map_fd < 0) {
        LOG_ERR("Map not initialized");
        return -1;
    }
    
    if (strlen(name) >= HIDDEN_FILES_SIZE) {
        LOG_ERR("Name too long: %zu >= %d", strlen(name), HIDDEN_FILES_SIZE);
        return -1;
    }
    
    char key[HIDDEN_FILES_SIZE] = {0};
    strncpy(key, name, HIDDEN_FILES_SIZE - 1);
    
    bpf_elem_attr_t attr = {
        .map_fd = hidden_map_fd,
        .key = (__u64)(unsigned long)key,
        .value = (__u64)(unsigned long)&value,
        .flags = BPF_ANY,
    };
    
    int ret = bpf_sys(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
    if (ret < 0) {
        return ret;
    }
    
    LOG("Added: '%s' -> %u", name, value);
    return 0;
}

/* Remove file from hidden list */
static int remove_hidden_file(const char *name)
{
    LOG("Removing: '%s'", name);
    
    if (hidden_map_fd < 0)
        return -1;
    
    char key[HIDDEN_FILES_SIZE] = {0};
    strncpy(key, name, HIDDEN_FILES_SIZE - 1);
    
    bpf_elem_attr_t attr = {
        .map_fd = hidden_map_fd,
        .key = (__u64)(unsigned long)key,
    };
    
    int ret = bpf_sys(BPF_MAP_DELETE_ELEM, &attr, sizeof(attr));
    if (ret < 0 && errno != ENOENT) {
        return ret;
    }
    
    LOG("Removed: '%s'", name);
    return 0;
}

/* List hidden files */
static void list_hidden_files(void)
{
    LOG("Listing hidden files...");
    
    if (hidden_map_fd < 0) {
        LOG_ERR("Map not initialized");
        return;
    }
    
    char next_key[HIDDEN_FILES_SIZE];
    int count = 0;
    
    while (1) {
        memset(next_key, 0, HIDDEN_FILES_SIZE);
        
        bpf_elem_attr_t attr = {
            .map_fd = hidden_map_fd,
            .key = 0,
            .next_key = (__u64)(unsigned long)next_key,
            .flags = 0,
        };
        
        int ret = syscall(__NR_bpf, BPF_MAP_GET_NEXT_KEY, &attr, sizeof(attr));
        if (ret < 0) {
            if (errno == ENOENT) {
                break;
            }
            LOG_ERR("GET_NEXT_KEY failed: %d", errno);
            break;
        }
        
        if (next_key[0] == '\0') {
            break;
        }
        
        __u32 val = 0;
        bpf_elem_attr_t lookup = {
            .map_fd = hidden_map_fd,
            .key = (__u64)(unsigned long)next_key,
            .value = (__u64)(unsigned long)&val,
            .flags = 0,
        };
        
        ret = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &lookup, sizeof(lookup));
        if (ret == 0) {
            LOG("  [%d] '%s' (%s)", count, next_key, val == 2 ? "dir" : "file");
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
    
    if (hidden_map_fd < 0)
        return;
    
    char key[HIDDEN_FILES_SIZE];
    int count = 0;
    
    while (1) {
        memset(key, 0, HIDDEN_FILES_SIZE);
        
        bpf_elem_attr_t attr = {
            .map_fd = hidden_map_fd,
            .key = 0,
            .next_key = (__u64)(unsigned long)key,
            .flags = 0,
        };
        
        int ret = syscall(__NR_bpf, BPF_MAP_GET_NEXT_KEY, &attr, sizeof(attr));
        if (ret < 0) {
            if (errno == ENOENT)
                break;
            break;
        }
        
        if (key[0] == '\0')
            break;
        
        bpf_elem_attr_t del = {
            .map_fd = hidden_map_fd,
            .key = (__u64)(unsigned long)key,
        };
        
        ret = syscall(__NR_bpf, BPF_MAP_DELETE_ELEM, &del, sizeof(del));
        if (ret >= 0) {
            count++;
        }
    }
    
    LOG("Cleared %d entries", count);
}

/* Print stats */
static void print_stats(void)
{
    LOG("=== Statistics ===");
    
    if (stats_map_fd < 0) {
        LOG("Stats map not available");
        return;
    }
    
    __u32 key;
    __u64 val;
    
    key = 0; /* calls */
    bpf_elem_attr_t attr = {
        .map_fd = stats_map_fd,
        .key = (__u64)(unsigned long)&key,
        .value = (__u64)(unsigned long)&val,
    };
    
    if (syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr)) == 0) {
        LOG("  getdents64 calls: %llu", val);
    }
    
    key = 1; /* hidden */
    if (syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr)) == 0) {
        LOG("  hidden entries: %llu", val);
    }
}

/* Load simple eBPF program inline */
static int load_bpf_program(void)
{
    LOG("=== Loading eBPF program ===");
    
    /*
     * Simple eBPF program that logs when getdents64 is called
     * This is a tracepoint program
     */
    
    /* eBPF instructions for tracepoint/sys_enter_getdents64 */
    /* 
     * r0 = 0 (return 0)
     * exit
     */
    struct bpf_insn {
        __u8 code;
        __u8 dst_reg:4;
        __u8 src_reg:4;
        __s16 off;
        __s32 imm;
    } prog[] = {
        /* r0 = 0 */
        { 0xb7, 0, 0, 0, 0 },
        /* exit */
        { 0x95, 0, 0, 0, 0 },
    };
    
    LOG_DEBUG("eBPF program: %zu instructions", sizeof(prog) / sizeof(prog[0]));
    
    /* For now, just log - full program loading requires CO-RE/btf */
    LOG("eBPF program loading skipped (requires BTF/CO-RE)");
    LOG("The hidden_files map is ready for use by kernel module");
    
    return 0;
}

/* Attach to tracepoint */
static int attach_tracepoint(void)
{
    LOG("=== Attaching to tracepoint ===");
    LOG("Note: Tracepoint attachment requires kernel module or bpf_link");
    
    /* On Android, actual tracepoint attachment is done via:
     * 1. A kernel module that loads the BPF program
     * 2. Or using bpf_link_create with BPF_TRACEPOINT
     * 
     * This userspace program only manages the maps
     */
    
    LOG("Maps created and ready:");
    LOG("  hidden_map_fd=%d", hidden_map_fd);
    LOG("  stats_map_fd=%d", stats_map_fd);
    LOG("  rb_map_fd=%d", rb_map_fd);
    
    return 0;
}

/* Print usage */
static void print_usage(const char *prog)
{
    printf("\n=== Android eBPF File Hiding Module v1.0 ===\n");
    printf("\nUsage: %s <command>\n\n", prog);
    printf("Commands:\n");
    printf("  add <file>       Hide a file\n");
    printf("  add-d <dir>      Hide a directory\n");
    printf("  remove <name>    Remove from hidden list\n");
    printf("  list             List all hidden files\n");
    printf("  stats            Show statistics\n");
    printf("  clear            Clear all hidden files\n");
    printf("  shell            Interactive shell mode\n");
    printf("  help             Show this help\n");
    printf("\n");
    printf("Note: This module creates BPF maps but requires a kernel\n");
    printf("component (module or bpf_link) to actually filter files.\n");
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
    printf("  sizeof(bpf_create_attr_t): %zu\n", sizeof(bpf_create_attr_t));
    printf("  sizeof(bpf_elem_attr_t): %zu\n", sizeof(bpf_elem_attr_t));
    printf("\n");
    
    if (__NR_bpf == 0) {
        LOG_ERR("bpf syscall not available!");
        return 1;
    }
    
    if (geteuid() != 0) {
        printf("[WARNING] Not running as root, BPF may fail\n\n");
    }
    
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGPIPE, SIG_IGN);
    
    /* Create maps */
    if (create_hidden_map() < 0) {
        LOG_ERR("Failed to create hidden_files map!");
        return 1;
    }
    
    if (create_stats_map() < 0) {
        LOG_ERR("Failed to create stats map!");
    }
    
    if (create_rb_map() < 0) {
        LOG_ERR("Failed to create ringbuf map!");
    }
    
    /* Load BPF program */
    load_bpf_program();
    
    /* Attach */
    attach_tracepoint();
    
    /* Add test entries if root */
    if (geteuid() == 0) {
        printf("\n[Adding default hidden entries for testing]\n");
        add_hidden_file(".hidden", 1);
        add_hidden_file(".nomedia", 0);
        add_hidden_file("test_file", 0);
        printf("\n");
    }
    
    /* Interactive mode */
    if (argc < 2 || (argc == 2 && strcmp(argv[1], "shell") == 0)) {
        printf("Entering interactive mode. Type 'help' for commands.\n\n");
        
        char line[512];
        while (running && fgets(line, sizeof(line), stdin)) {
            line[strcspn(line, "\n")] = 0;
            
            if (line[0] == '\0')
                continue;
            
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
            } else if (strcmp(cmd, "stats") == 0) {
                print_stats();
            } else if (strcmp(cmd, "clear") == 0) {
                clear_hidden_list();
            } else if (strcmp(cmd, "help") == 0) {
                print_usage(argv[0]);
            } else if (cmd[0]) {
                LOG_ERR("Unknown command: %s", cmd);
            }
            
            memset(line, 0, sizeof(line));
        }
    } else {
        if (strcmp(argv[1], "add") == 0 && argc > 2) {
            return add_hidden_file(argv[2], 0);
        } else if (strcmp(argv[1], "add-d") == 0 && argc > 2) {
            return add_hidden_file(argv[2], 1);
        } else if (strcmp(argv[1], "remove") == 0 && argc > 2) {
            return remove_hidden_file(argv[2]);
        } else if (strcmp(argv[1], "list") == 0) {
            list_hidden_files();
        } else if (strcmp(argv[1], "stats") == 0) {
            print_stats();
        } else if (strcmp(argv[1], "clear") == 0) {
            clear_hidden_list();
        } else {
            print_usage(argv[0]);
        }
    }
    
    /* Cleanup */
    if (hidden_map_fd >= 0) close(hidden_map_fd);
    if (stats_map_fd >= 0) close(stats_map_fd);
    if (rb_map_fd >= 0) close(rb_map_fd);
    
    printf("\n[hook] Exiting\n");
    return 0;
}
