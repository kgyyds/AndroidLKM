# HOOK - File Hiding Module Makefile
# ARM64 compatible, 5.10 cross-version

obj-m := hook.o
hook-objs := hook_manager.o vfs_hook.o

ccflags-y := -Wno-error

all:
	@echo "Usage: make ARCH=arm64 CC=clang modules"

modules:
	$(MAKE) -C $(KDIR) M=$(PWD) ARCH=$(ARCH) CC=$(CC) modules

clean:
	rm -f *.o *.ko *.mod.c modules.order *.mod *.symvers .*.cmd 2>/dev/null
	rm -rf .tmp_versions Module.symvers .version
