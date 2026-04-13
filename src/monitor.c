#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "../ebpf/monitor.skel.h"

// Define the incoming event structure matched with the BPF program
struct syscall_event {
 __u32 pid;
 __u32 syscall_nr;
 __u64 timestamp_ns;
 char comm[16]; // Process name
};

// Very simple argument parser extracting `-p <PID>` and `-w <SYSCALL_LIST>` arguments
static int parse_arguments(int argc, char *argv[], __u32 *pid, __u32 *call_nums, int *count){
    int m = 0;
    for(int i = 1; i < argc; i++){
        if((strcmp(argv[i],"-w") == 0) && i != argc-1){
            char *tok = strtok(argv[i+1], ",");
            while(tok){
                call_nums[m] = atoi(tok);
                (*count)++;
                m += 1;
                tok = strtok(NULL, ",");
            }
        }else if((strcmp(argv[i],"-p") == 0)  && i != argc-1){
            *pid = atoi(argv[i+1]);
        }
    }
    return 0;
}

// Volatile flag toggled when the terminal sends Ctrl+C (SIGINT)
static volatile bool exiting = false;

static void sig_handler(int sig) {
    (void)sig; // Silence compiler warning natively
    exiting = true;
}

// Callback triggered dynamically whenever the eBPF RingBuffer has incoming data
static int callback(void *ctx, void *data, size_t size){
    (void)ctx;
    (void)size;

    struct syscall_event *event = data; 
    printf("[%s] pid=%u syscall=%u\n", event->comm, event->pid, event->syscall_nr);
    return 0;
}

int main(int argc, char *argv[])
{
    struct ring_buffer *ring_buffer_monitor = NULL;

    __u32 call_nums[32];
    int count = 0;
    __u32 pid = 0;

    parse_arguments(argc, argv, &pid, call_nums, &count);

    // Instantiate and fetch standard eBPF skeleton context
    struct monitor_bpf *skel;
    int err;
    
    // Open the auto-compiled monitor.skel.h binary and load it globally into kernel memory
    skel = monitor_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton ---> Bad thing\n");
        return 1;
    }
    printf("BPF skeleton opened and loaded ---> Good thing\n");

    // Attack the loaded BPF program hook locations declared strictly inside `monitor.bpf.c`
    err = monitor_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton ---> Bad thing\n");
        goto cleanup;
    }
    printf("BPF skeleton was attached ---> Good thing\n");

    __u8 value = 1;

    // Dynamically insert items into Map File Descriptors bridging Kernel filters to target elements!
    bpf_map_update_elem(bpf_map__fd(skel->maps.tracked_pids), &pid, &value, BPF_ANY);
    for(int i = 0; i < count; i++){
        bpf_map_update_elem(bpf_map__fd(skel->maps.watched_syscalls), &call_nums[i], &value, BPF_ANY);
    }

    // Force map unlinking inside BPF Filesystem just in case prior executions cleanly exited 
    unlink("/sys/fs/bpf/tracked_pids");
    bpf_map__pin(skel->maps.tracked_pids, "/sys/fs/bpf/tracked_pids");

    unlink("/sys/fs/bpf/watched_syscalls");
    bpf_map__pin(skel->maps.watched_syscalls, "/sys/fs/bpf/watched_syscalls");

    // Bind generic C-level ring_buffer listening functions to the kernel RingBuffer map
    int map_fd = bpf_map__fd(skel->maps.events);
    ring_buffer_monitor = ring_buffer__new(map_fd, callback, NULL, NULL);

    if(!ring_buffer_monitor){
        fprintf(stderr, "Failed to create new ring buffer ---> Bad thing\n");
        goto cleanup;  
    }

    // Assign generic Kill Hooks to toggle polling loop closures 
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // Repeatedly query RingBuffer loop 500ms times until kill signal arrives (exiting flag is set via thread interruption)
    while(!exiting){
        err = ring_buffer__poll(ring_buffer_monitor, 500);
        if (err == -EINTR) {
            break;
        }
    }

    cleanup:
        printf("\nCleaning up...\n");
        if(ring_buffer_monitor){
            ring_buffer__free(ring_buffer_monitor); // Properly free RingBuffer references
        }

        // Wipe BPF FileSystem linkages to free map instances safely
        unlink("/sys/fs/bpf/tracked_pids");
        unlink("/sys/fs/bpf/watched_syscalls");

        // Tear down global application scope cleanly natively mapping back memory
        if (skel) {
            monitor_bpf__destroy(skel); 
        }
        return -err;

    return 0;
}
