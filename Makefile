# HOOK eBPF Makefile
# File hiding module using eBPF

MDIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

# Toolchain
CLANG ?= clang
LLC ?= llc
BPFTOOL ?= bpftool
CC ?= gcc

# BPF compilation flags
BPF_TARGET := bpf
BPF_CFLAGS := -Wall -Wno-unused-value -Wno-pointer-sign \
               -Wno-compare-distinct-pointer-types \
               -O2 -target $(BPF_TARGET) -emit-llvm \
               -I$(MDIR)

# Userspace compilation flags  
CFLAGS := -Wall -O2 -g

# Output files
BPF_OBJ := $(MDIR)/hook.bpf.o
SKEL_HDR := $(MDIR)/hook.skel.h
VMLINUX_HDR := $(MDIR)/vmlinux.h
LOADER_HOST := $(MDIR)/hook_loader
LOADER_ANDROID := $(MDIR)/hook_android

# Sources
BPF_SRC := hook.bpf.c
LOADER_SRC := hook_loader.c
ANDROID_SRC := hook_android.c

# Default target
.PHONY: all
all: bpf skeleton loader

# Build BPF object
.PHONY: bpf
bpf: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC) $(VMLINUX_HDR)
	@echo "  CLANG-BPF $(notdir $@)"
	$(CLANG) $(BPF_CFLAGS) -c $< -o - 2>/dev/null | \
		$(LLC) -march=bpf -filetype=obj -o $@ || \
		$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# Generate skeleton header
.PHONY: skeleton
skeleton: $(SKEL_HDR)

$(SKEL_HDR): $(BPF_OBJ)
	@echo "  BPFTOOL gen skeleton $(notdir $@)"
	@$(BPFTOOL) gen skeleton $< > $@ 2>/dev/null || \
		echo "/* Skeleton not generated */"

# Build userspace loader (host)
.PHONY: loader
loader: $(LOADER_HOST)

$(LOADER_HOST): $(LOADER_SRC) $(SKEL_HDR)
	@echo "  CC $(notdir $@)"
	$(CC) $(CFLAGS) -o $@ $(LOADER_SRC) -lbpf -lelf

# Build Android binary
.PHONY: android
android: $(LOADER_ANDROID)

$(LOADER_ANDROID): $(ANDROID_SRC)
	@echo "  Building Android ARM64 binary"
	@if [ -n "$$ANDROID_NDK_ROOT" ]; then \
		export PATH=$$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin:$$PATH; \
		aarch64-linux-android34-clang -static -o $@ $<; \
	elif [ -d "$$HOME/android-ndk" ]; then \
		export PATH=$$HOME/android-ndk/toolchains/llvm/prebuilt/linux-x86_64/bin:$$PATH; \
		aarch64-linux-android34-clang -static -o $@ $<; \
	else \
		echo "Android NDK not found, skipping Android build"; \
	fi

# Clean
.PHONY: clean
clean:
	rm -f $(BPF_OBJ) $(SKEL_HDR) $(LOADER_HOST) $(LOADER_ANDROID)
	rm -f $(VMLINUX_HDR)
	rm -f *.o *.skel.h hook_loader hook_android

# Help
.PHONY: help
help:
	@echo "HOOK eBPF File Hiding Module"
	@echo ""
	@echo "Targets:"
	@echo "  all      - Build everything (BPF + loader)"
	@echo "  bpf      - Build BPF object file"
	@echo "  skeleton - Generate BPF skeleton header"
	@echo "  loader   - Build host userspace loader"
	@echo "  android  - Build Android ARM64 binary"
	@echo "  clean    - Remove build artifacts"
	@echo ""
	@echo "Requirements:"
	@echo "  - clang with BPF target support"
	@echo "  - llvm LLC"
	@echo "  - bpftool (for skeleton generation)"
	@echo "  - libbpf-dev (for host loader)"
	@echo ""
	@echo "Android Build:"
	@echo "  ANDROID_NDK_ROOT=/path/to/ndk make android"
