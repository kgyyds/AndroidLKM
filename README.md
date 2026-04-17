# HOOK - eBPF File Hiding Module

基于 eBPF 的文件/文件夹隐藏模块，使用 tracepoint 监控 `getdents64` 系统调用。

## 功能

- **eBPF 监控**: 通过 tracepoint 监控目录遍历
- **隐藏列表管理**: 通过 `/dev/hidefile` 设备节点管理
- **实时日志**: 通过 ringbuffer 实时监控隐藏事件
- **统计信息**: 支持查看调用统计

## 架构

```
                    +------------------+
                    |  eBPF Program    |
                    | hook.bpf.c       |
                    +--------+---------+
                             |
              +--------------+--------------+
              |                             |
    +---------v---------+         +---------v---------+
    |  Tracepoint       |         |  Ringbuffer        |
    |  sys_exit_getdents| --------> |  (events)         |
    +-------------------+         +-------------------+
                                           |
                                  +---------v---------+
                                  |  Polling Thread   |
                                  +-------------------+

    +-------------------+         +-------------------+
    |  Hidden Files Map | <------ |  Userspace Loader |
    |  (BPF Hash Map)   |         |  hook_loader.c    |
    +-------------------+         +--------+----------+
                                            |
                                   +--------v----------+
                                   |  /dev/hidefile     |
                                   |  (control device)  |
                                   +--------------------+
```

## 编译

### 依赖

```bash
# Ubuntu/Debian
sudo apt install clang llvm libbpf-dev pkg-config

# 需要 bpftool (来自 linux-tools)
sudo apt install linux-tools-$(uname -r)
```

### 编译

```bash
make
```

### 运行

```bash
sudo ./hook_loader
```

## 使用

```bash
# 隐藏文件
echo "secret.txt" > /dev/hidefile

# 隐藏目录
echo "d:hidden_dir" > /dev/hidefile

# 列出当前隐藏的文件
echo "list" > /dev/hidefile

# 查看统计信息
echo "stats" > /dev/hidefile

# 清除所有隐藏
echo "clear" > /dev/hidefile
```

## 注意事项

此版本基于 **eBPF monitoring** 架构：
- eBPF 程序通过 tracepoint 监控 `getdents64`
- 识别隐藏的条目并通过 ringbuffer 上报
- 实际的隐藏逻辑通过扩展实现

如需更完整的隐藏功能，可以结合内核模块使用。

## 目录结构

```
AndroidLKM/
├── hook.bpf.c        # eBPF 程序
├── hook_loader.c     # 用户空间加载器
├── hook.h            # 头文件
├── Makefile          # 编译配置
├── README.md         # 本文档
└── .github/workflows/
    └── build-ebpf.yml  # CI 配置
```

## 许可证

GPL v2
