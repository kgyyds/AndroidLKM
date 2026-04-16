# HOOK - File Hiding Module Makefile
# 与 KernelSU 相同的编译方式

KDIR := $(KDIR)
MDIR := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))

$(info -- KDIR: $(KDIR))
$(info -- MDIR: $(MDIR))

.PHONY: all clean

all:
	make -C $(KDIR) M=$(MDIR) modules -j$(shell nproc)

clean:
	make -C $(KDIR) M=$(MDIR) clean

# 和 KernelSU 完全一样的 obj 语法
obj-$(CONFIG_HOOK) += hook.o
hook-objs := hook_manager.o vfs_hook.o

# 关键编译参数 - 和 KernelSU 一样
ccflags-y += -I$(src)
ccflags-y += -Wno-strict-prototypes -Wno-int-conversion -Wno-gcc-compat -Wno-missing-prototypes
ccflags-y += -Wno-declaration-after-statement -Wno-unused-function
