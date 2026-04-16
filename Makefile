# HOOK - File Hiding Module Makefile
# ARM64 compatible, 5.10 cross-version

CONFIG_HOOK := m

obj-m += hook.o
hook-objs := hook_manager.o vfs_hook.o

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f *.o *.ko *.mod.c modules.order *.mod *.symvers .*.cmd 2>/dev/null
	rm -rf .tmp_versions Module.symvers .version
