# Syscall Sandbox

System call interception, process tracing, and kernel observability, built from three
cooperating pieces: an eBPF monitor, a kernel module, and a `ptrace` sandbox.

## Overview

The project observes and blocks Linux syscalls on a per-process (and per-process-tree)
basis using three integrated components:

1. **eBPF Monitor** — attaches to the `raw_syscalls/sys_enter` tracepoint and emits an
   event to userspace whenever a *tracked* process invokes a *watched* syscall.
2. **Kernel Module** — maintains the list of tracked PIDs and blocked syscalls, and
   automatically follows process trees (parent + descendants) via the
   `sched_process_fork` tracepoint. Exposes its state through `/proc/syscall_sandbox`.
3. **ptrace Sandbox** — traces a target program and intercepts syscalls, either *blocking*
   them (returning `-1`) or *killing* the process on first use.

A helper tool, `bpf-bridge`, connects the eBPF monitor's pinned BPF map to the kernel
module so that process-tree tracking updates the map in real time.

## How it works

### 1. eBPF Monitor (`ebpf/monitor.bpf.c`, `src/monitor.c`)

The BPF program attaches to `tracepoint/raw_syscalls/sys_enter`, which fires for every
syscall on the system. For each call it:

- extracts the PID from `bpf_get_current_pid_tgid()`,
- checks the PID against the `tracked_pids` hash map,
- checks the syscall number against the `watched_syscalls` hash map,
- and, on a match, reserves a slot in a ring buffer and streams a
  `{pid, syscall_nr, timestamp_ns, comm}` event to userspace.

The userspace monitor (`src/monitor.c`) populates the two maps from the command line
(`-p PID`, `-w "n1,n2,..."`), pins them to `/sys/fs/bpf/` (so the kernel module can share
them), and polls the ring buffer, printing events as they arrive.

### 2. Kernel Module (`module/syscall_module.c`)

Loads as `syscall_module.ko` and registers `/proc/syscall_sandbox`. It keeps two kernel
doubly-linked lists — `tracked_pids` and `blocked_syscalls` — guarded by a spinlock, and
registers a `sched_process_fork` tracepoint probe so that when a tracked process forks,
its child is tracked automatically (recursively tracking the whole process tree).

The proc file doubles as a control channel:

| Command             | Effect                                  |
|---------------------|-----------------------------------------|
| `+N`                | Add syscall number `N` to the blocklist |
| `-N`                | Remove syscall number `N`               |
| `clear`             | Clear the blocklist                      |
| `register PID`      | Track PID (and its descendants)          |
| `setmap FD`         | Attach a userspace BPF map by fd         |

Reading the file prints the current state. When a BPF map is attached via `setmap`, each
tracked PID is written directly into the shared eBPF `tracked_pids` map, so the monitor
sees the dynamically-tracked children immediately.

### 3. ptrace Sandbox (`src/sandbox.c`)

`fork`s a child, asks it to `PTRACE_TRACEME`, then resumes it with
`PTRACE_SYSCALL`. Using `PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE`,
it follows forks/clones so the whole process tree is traced. On each syscall entry it
reads `orig_rax`; if the number is blocklisted it either rewrites `orig_rax` to `-1`
(blocking) or sends `SIGKILL` (with `-k`).

## Repository layout

| Path                      | Description                                             |
|---------------------------|---------------------------------------------------------|
| `src/sandbox.c`           | ptrace-based syscall interceptor                        |
| `src/monitor.c`           | eBPF monitor userspace driver                           |
| `src/bpf_bridge.c`        | Bridges the pinned eBPF map to the kernel module        |
| `src/syscall_tester.c`    | Utility that repeatedly invokes a syscall               |
| `ebpf/monitor.bpf.c`      | eBPF program (kernel side)                              |
| `ebpf/Makefile`           | Generates `vmlinux.h` and compiles the BPF object       |
| `module/syscall_module.c` | Kernel module: PID tree + blocklist + `/proc` interface |
| `module/Makefile`         | Builds/loads the kernel module                          |

## Prerequisites

- Linux kernel with BTF enabled (`CONFIG_DEBUG_INFO_BTF=y`)
- `clang`, `llvm`, and `bpftool`
- `libbpf` (development headers)
- `cmake`
- Kernel headers/build tree matching the running kernel (for the module)

## Building

```bash
# 1. Generate vmlinux.h and compile the eBPF program
cd ebpf && make

# 2. Build the userspace tools
mkdir -p build && cd build
cmake ..
make

# 3. Build the kernel module
cd ../module && make
```

## Usage

Run each component in its own terminal.

```bash
# Terminal 1: eBPF monitor — watch syscalls 41 (socket) & 257 (openat) for PID 1234
sudo ./build/monitor -p 1234 -w "41,257"

# Terminal 2: load the kernel module, then bridge the BPF map
sudo insmod module/syscall_module.ko
sudo ./build/bpf-bridge

# Terminal 3: register a process tree and block a syscall
echo "register $$" | sudo tee /proc/syscall_sandbox   # track this shell + children
echo "+41"         | sudo tee /proc/syscall_sandbox   # block socket

./build/sandbox -b 41 -- ./build/syscall_tester 41    # block syscall 41 in the tester
./build/sandbox -k 41 -- ./build/syscall_tester 41    # kill on syscall 41 instead
```

Inspect current state at any time:

```bash
cat /proc/syscall_sandbox
```

Clean up:

```bash
sudo rmmod syscall_module
```
