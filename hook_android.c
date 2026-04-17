/*
 * hook_android.c - Android File Monitor
 * 
 * 监控 getdents64 系统调用，记录文件和目录访问日志
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <dirent.h>
#include <time.h>

/* Log to stdout */
#define LOG(fmt, ...) fprintf(stdout, "[hook] " fmt "\n", ##__VA_ARGS__)
#define LOG_ERR(fmt, ...) fprintf(stderr, "[hook:ERROR] " fmt "\n", ##__VA_ARGS__)

/* getdents64 syscall number */
#ifndef __NR_getdents64
#if defined(__aarch64__)
#define __NR_getdents64 61
#elif defined(__arm__)
#define __NR_getdents64 61
#elif defined(__x86_64__)
#define __NR_getdents64 61
#else
#define __NR_getdents64 0
#endif
#endif

/* Linux directory entry */
struct linux_dirent64 {
    unsigned long long d_ino;
    signed long long d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[256];
};

/* Directory entry types */
static const char* d_type_name(unsigned char type)
{
    switch (type) {
        case DT_FIFO: return "FIFO";
        case DT_CHR:  return "CHR";
        case DT_DIR:  return "DIR";
        case DT_BLK:  return "BLK";
        case DT_REG:  return "REG";
        case DT_LNK:  return "LNK";
        case DT_SOCK: return "SOCK";
        case DT_UNKNOWN: return "UNKNOWN";
        default: return "???";
    }
}

/* Get current timestamp */
static void get_timestamp(char *buf, size_t len)
{
    struct timespec ts;
    struct tm *tm;
    
    clock_gettime(CLOCK_REALTIME, &ts);
    tm = localtime(&ts.tv_sec);
    snprintf(buf, len, "%02d:%02d:%02d.%06ld", 
             tm->tm_hour, tm->tm_min, tm->tm_sec, ts.tv_nsec / 1000);
}

/* Monitor directory reads */
static void monitor_directory(const char *path)
{
    LOG("=== Monitoring directory: %s ===", path);
    
    int fd = open(path, O_RDONLY | O_DIRECTORY);
    if (fd < 0) {
        LOG_ERR("Failed to open '%s': %s", path, strerror(errno));
        return;
    }
    
    LOG("Opened directory: %s (fd=%d)", path, fd);
    
    char buf[65536];
    char timestamp[32];
    int total_entries = 0;
    int total_dirs = 0;
    int total_files = 0;
    int total_other = 0;
    
    while (1) {
        int ret = syscall(__NR_getdents64, fd, buf, sizeof(buf));
        
        if (ret < 0) {
            if (errno == EINTR) continue;
            LOG_ERR("getdents64 failed: %s", strerror(errno));
            break;
        }
        
        if (ret == 0) {
            break;  /* End of directory */
        }
        
        /* Parse directory entries */
        int offset = 0;
        while (offset < ret) {
            struct linux_dirent64 *dent = (struct linux_dirent64 *)(buf + offset);
            
            if (dent->d_reclen == 0) {
                break;
            }
            
            total_entries++;
            
            /* Count by type */
            switch (dent->d_type) {
                case DT_DIR:
                    total_dirs++;
                    break;
                case DT_REG:
                    total_files++;
                    break;
                default:
                    total_other++;
            }
            
            /* Log entry */
            get_timestamp(timestamp, sizeof(timestamp));
            LOG("[%s] %-6s %s", 
                d_type_name(dent->d_type), 
                dent->d_name,
                (dent->d_type == DT_DIR) ? "/" : "");
            
            offset += dent->d_reclen;
        }
    }
    
    close(fd);
    
    /* Summary */
    LOG("=== Summary for %s ===", path);
    LOG("  Total entries: %d", total_entries);
    LOG("  Directories:   %d", total_dirs);
    LOG("  Files:         %d", total_files);
    LOG("  Other:         %d", total_other);
}

/* Print usage */
static void print_usage(const char *prog)
{
    printf("\n=== Android File Monitor ===\n");
    printf("\nUsage: %s <path> [path2] [...]\n", prog);
    printf("\nMonitor directory and file access via getdents64 syscall.\n");
    printf("\nExamples:\n");
    printf("  %s /sdcard\n", prog);
    printf("  %s /sdcard/Download /sdcard/DCIM\n", prog);
    printf("\n");
}

/* Interactive shell mode */
static void shell_mode(void)
{
    char line[1024];
    
    printf("\n=== File Monitor Shell ===\n");
    printf("Commands:\n");
    printf("  monitor <path>  - Monitor a directory\n");
    printf("  list <path>     - List directory contents\n");
    printf("  help            - Show this help\n");
    printf("  exit            - Exit\n\n");
    
    while (1) {
        printf("hook> ");
        fflush(stdout);
        
        if (!fgets(line, sizeof(line), stdin)) {
            break;
        }
        
        /* Remove newline */
        line[strcspn(line, "\n")] = 0;
        
        if (strcmp(line, "exit") == 0 || strcmp(line, "quit") == 0) {
            break;
        }
        
        if (strncmp(line, "monitor ", 8) == 0) {
            monitor_directory(line + 8);
        } else if (strncmp(line, "list ", 5) == 0) {
            monitor_directory(line + 5);
        } else if (strcmp(line, "help") == 0) {
            printf("Commands:\n");
            printf("  monitor <path>  - Monitor a directory\n");
            printf("  list <path>    - List directory contents\n");
            printf("  help            - Show this help\n");
            printf("  exit            - Exit\n");
        } else if (strlen(line) > 0) {
            /* Try as path */
            monitor_directory(line);
        }
    }
}

static void sig_handler(int sig)
{
    (void)sig;
    printf("\n[hook] Interrupted, exiting...\n");
    exit(0);
}

int main(int argc, char **argv)
{
    printf("\n=== Android File Monitor v1.0 ===\n");
    printf("=== Monitor getdents64 syscall ===\n\n");
    
    printf("[System Info]\n");
    printf("  getdents64 syscall: %d\n", __NR_getdents64);
    printf("  uid: %d\n", getuid());
    printf("\n");
    
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    if (argc < 2) {
        printf("No paths specified, entering shell mode.\n\n");
        shell_mode();
    } else if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        print_usage(argv[0]);
    } else if (strcmp(argv[1], "shell") == 0) {
        shell_mode();
    } else {
        /* Monitor each specified path */
        for (int i = 1; i < argc; i++) {
            printf("\n");
            monitor_directory(argv[i]);
            printf("\n");
        }
    }
    
    return 0;
}
