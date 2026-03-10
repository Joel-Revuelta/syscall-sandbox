CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool

ARCH := $(shell uname -m | sed 's/x86_64/x86/')
LIBBPF_INCLUDES := $(shell pkg-config --cflags libbpf 2>/dev/null || echo "-I/usr/include")

.PHONY: all clean vmlinux.h

all: vmlinux.h monitor.bpf.o

# Generate vmlinux.h from running kernel's BTF
vmlinux.h:
	@echo "Generating vmlinux.h from kernel BTF..."
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@
	@echo "Generated vmlinux.h ($(shell wc -l < $@) lines)"

# Compile eBPF program
monitor.bpf.o: monitor.bpf.c vmlinux.h
	$(CLANG) -g -O2 -target bpf \
		-D__TARGET_ARCH_$(ARCH) \
		$(LIBBPF_INCLUDES) \
		-c $< -o $@
	@echo "Compiled monitor.bpf.o"

clean:
	rm -f vmlinux.h monitor.bpf.o

# Verify the compiled program
verify: monitor.bpf.o
	$(BPFTOOL) prog load $< /sys/fs/bpf/test_monitor && \
	$(BPFTOOL) prog show pinned /sys/fs/bpf/test_monitor && \
	rm /sys/fs/bpf/test_monitor
