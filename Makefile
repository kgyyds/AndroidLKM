# HOOK - 内核通用 Hook 框架 Makefile
# 支持 Linux 5.10 - 6.12 内核，多架构兼容

# 模块名称
obj-m := hook.o

# 源文件
hook-objs := hook_manager.o kprobe_hook.o vfs_hook.o

# 架构特定源文件
ifeq ($(ARCH),arm64)
    hook-objs += arm64/syscall_hook.o arm64/patch_memory.o
endif

# 内核版本检查 (可选)
KSU_EXPECTED_SIZE2 ?=
KSU_EXPECTED_HASH2 ?=

# 默认目标
all:
	@echo "Usage:"
	@echo "  make ARCH=arm64 CC=clang        - 编译 arm64 版本"
	@echo "  make ARCH=x86_64 CC=clang      - 编译 x86_64 版本"
	@echo "  make clean                     - 清理"
	@echo ""
	@echo "DDK 编译示例:"
	@echo "  make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- CC=clang"

# 编译模块
modules:
	$(MAKE) -C $(KDIR) M=$(PWD) ARCH=$(ARCH) CC=$(CC) modules

# 清理
clean:
	rm -f *.o arm64/*.o x86_64/*.o modules.order *.mod.c *.mod *.ko .*.cmd .cacheindex 2>/dev/null
	rm -rf .tmp_versions Module.symvers .version

# 获取内核版本
KVER ?= $(shell uname -r 2>/dev/null || echo "5.10.0")
KDIR ?= /lib/modules/$(KVER)/build

# 直接编译（用于本地测试）
%.o: %.c
	$(CC) $(KBUILD_CFLAGS) -I$(src)/include -c -o $@ $<

# 依赖
depend:
	@echo "依赖: Linux 内核头文件"
	@echo "  Ubuntu/Debian: apt install linux-headers-$$(uname -r)"
	@echo "  Android: 使用 DDK 镜像"
