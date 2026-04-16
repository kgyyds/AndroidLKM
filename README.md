# HOOK - 内核通用 Hook 框架

跨内核版本 (5.10 - 6.12) 的内核 Hook 框架，支持文件/文件夹隐藏功能。

## 功能

- **VFS Hook**: hook `getdents64` 过滤目录列表
- **Kprobe**: 通用 Kprobe Hook 支持
- **隐藏文件/文件夹**: 添加到隐藏列表的条目将从目录遍历中移除
- **多架构**: 支持 arm64 和 x86_64

## 编译

### 本地编译

```bash
# arm64
make ARCH=arm64 CC=clang

# x86_64
make ARCH=x86_64 CC=clang
```

### DDK 编译 (多内核版本)

使用 GitHub Actions 自动编译：
- 访问 Actions -> Build HOOK Kernel Module -> Run workflow

支持的版本:
- android12-5.10 (arm64, x86_64)
- android13-5.10 (arm64, x86_64)
- android13-5.15 (arm64, x86_64)
- android14-5.15 (arm64, x86_64)
- android14-6.1 (arm64, x86_64)
- android15-6.6 (arm64, x86_64)
- android16-6.12 (arm64, x86_64)

## API

### 隐藏文件/文件夹

```c
#include "hook.h"

// 添加隐藏文件
add_hidden_file("secret.txt", false);

// 添加隐藏文件夹
add_hidden_file("hidden_dir", true);

// 移除隐藏
remove_hidden_file("secret.txt");

// 检查是否隐藏
is_hidden("secret.txt", false);

// 清空隐藏列表
clear_hidden_list();
```

## 目录结构

```
HOOK/
├── .github/workflows/     # CI 配置
├── include/              # 头文件
├── arm64/                # ARM64 架构代码
├── x86_64/              # x86_64 架构代码
├── hook_manager.c       # 核心管理器
├── kprobe_hook.c        # Kprobe 实现
├── vfs_hook.c           # VFS Hook 实现
├── Makefile
└── README.md
```

## 许可证

GPL v2
