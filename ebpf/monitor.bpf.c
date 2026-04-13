#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Structure of the event data sent to Userspace via the RingBuffer
struct syscall_event {
    __u32 pid;
    __u32 syscall_nr;
    __u64 timestamp_ns;
    char comm[16]; // Process name
};

// Hash map to store PIDs that we want to track
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);  // Key is the PID
    __type(value, __u8); // Value works as a boolean flag (1 = tracked)
} tracked_pids SEC(".maps");

// Hash map to store specific syscall numbers we are watching
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);  // Key is the Syscall Number
    __type(value, __u8); // Value works as a boolean flag
} watched_syscalls SEC(".maps");

// RingBuffer map to efficiently stream syscall events up to Userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB buffer size
} events SEC(".maps");

// Attach to the raw_syscalls/sys_enter tracepoint to catch all syscalls universally
SEC("tracepoint/raw_syscalls/sys_enter")
int handle_sys_enter(struct trace_event_raw_sys_enter *ctx)
{
    // Retrieve the process ID calling the syscall (top 32 bits of pid_tgid)
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    // Look up if this PID is being tracked; if not, ignore the syscall
    __u8 *pid_tracked = bpf_map_lookup_elem(&tracked_pids, &pid);
    if (!pid_tracked)
        return 0;

    // Retrieve the syscall number and check if it's being watched
    __u32 syscall_nr = ctx->id;
    __u8 *syscall_tracked = bpf_map_lookup_elem(&watched_syscalls, &syscall_nr);
    if (!syscall_tracked)
        return 0;

    // Reserve space inside the RingBuffer for our event
    struct syscall_event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0; // Drop event if the buffer is full

    // Populate the event data
    e->pid = pid;
    e->syscall_nr = syscall_nr;
    e->timestamp_ns = bpf_ktime_get_ns(); // High-precision kernel timestamp
    bpf_get_current_comm(&e->comm, sizeof(e->comm)); // Fetch process name

    // Submit the event to Userspace
    bpf_ringbuf_submit(e, 0);

    return 0;
}

// BPF programs must be explicitly licensed under GPL to use certain kernel helpers
char LICENSE[] SEC("license") = "GPL";
