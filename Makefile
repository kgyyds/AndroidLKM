# HOOK - 文件隐藏模块 Makefile
# 使用 Ftrace 框架
# 支持 Linux 5.7 - 6.12

obj-m := hook.o
hook-objs := hook_manager.o

all:
	@echo "Usage:"
	@echo "  make ARCH=arm64 CC=clang        - 编译 arm64 版本"
	@echo "  make clean                      - 清理"

modules:
	$(MAKE) -C $(KDIR) M=$(PWD) ARCH=$(ARCH) CC=$(CC) modules

clean:
	rm -f *.o *.ko *.mod.c modules.order *.mod *.symvers .*.cmd 2>/dev/null
	rm -rf .tmp_versions Module.symvers .version
