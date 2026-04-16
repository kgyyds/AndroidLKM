# HOOK - File Hiding Module Makefile
# ARM64/x86_64 compatible, supports multiple kernel versions

CONFIG_HOOK := m
ARCH ?= arm64

# Cross compilation settings
ifeq ($(ARCH),arm64)
    CROSS_COMPILE := aarch64-linux-gnu-
    CC := clang
else ifeq ($(ARCH),x86_64)
    CROSS_COMPILE := x86_64-linux-gnu-
    CC := clang
endif

obj-m += hook.o
hook-objs := hook_manager.o vfs_hook.o

# Extra compile flags
ccflags-y += -I$(src)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) ARCH=$(ARCH) CC=$(CC) modules

help:
	@echo "HOOK Module Makefile"
	@echo ""
	@echo "Usage:"
	@echo "  make KDIR=/path/to/kernel ARCH=arm64 CC=clang"
	@echo ""
	@echo "Arguments:"
	@echo "  KDIR   - Path to kernel source (required)"
	@echo "  ARCH   - Architecture: arm64 or x86_64 (default: arm64)"
	@echo "  CC     - Compiler: clang (default)"
	@echo ""
	@echo "Example:"
	@echo "  # With DDK:"
	@echo "  ddk build -e CONFIG_HOOK=m ARCH=arm64 CC=clang"
	@echo ""
	@echo "  # With manual kernel path:"
	@echo "  make KDIR=~/android/kernel CC=clang"

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f *.o *.ko *.mod.c modules.order *.mod *.symvers .*.cmd 2>/dev/null
	rm -rf .tmp_versions Module.symvers .version
