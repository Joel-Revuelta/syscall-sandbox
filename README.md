[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-22041afd0340ce965d47ae6ef1cefeee28c7c493a6346c4f15d667ab976d596c.svg)](https://classroom.github.com/a/nyiCfx6J)
# COMP304 Project 2: Syscall Sandbox

System call interception, process tracing, and kernel observability.

## Overview

Build a syscall sandbox with three integrated components:
1. **eBPF Monitor** - Observes syscalls made by specified processes
2. **Kernel Module** - Tracks process trees (parent + descendants)
3. **ptrace Sandbox** - Intercepts and blocks specified syscalls

## Building

```bash
# Generate vmlinux.h and build eBPF
cd ebpf && make

# Build userspace tools
mkdir build && cd build
cmake ..
make

# Build kernel module

cd module && make
```


## Components

| File | Description |
|------|-------------|
| `src/sandbox.c` | ptrace sandbox [IMPLEMENT] |
| `src/monitor.c` | eBPF monitor [IMPLEMENT] |
| `ebpf/monitor.bpf.c` | eBPF program [IMPLEMENT] |
| `module/syscall_module.c` | Kernel module [IMPLEMENT] |
| `src/bpf_bridge.c` | eBPF ↔ kernel bridge (provided) |
| `src/syscall_tester.c` | Test utility (provided) |

## Quick Start
```bash
# Terminal 1: Start eBPF monitor
./monitor

# Terminal 2: Load kernel module and bridge
sudo insmod module/syscall_module.ko
sudo ./bpf-bridge

# Terminal 3: Configure and run sandbox
echo "+41" | sudo tee /proc/syscall_sandbox
echo "register $$" | sudo tee /proc/syscall_sandbox # register current shell (all of its children too)

./program # should trigger monitor event

./sandbox -b 41 -- ./program # should block syscall 41 in program
```

## Challenges <For you to fill in>

This section is for you to fill
