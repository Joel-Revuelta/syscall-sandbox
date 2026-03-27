#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "../ebpf/monitor.skel.h"

struct syscall_event {
 __u32 pid;
 __u32 syscall_nr;
 __u64 timestamp_ns;
 char comm[16]; // process name
};

static int parse_arguements(int argc, char *argv[], __u32 *pid, __u32 *call_nums, int *count){

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

static int callback(void *ctx, void *data, size_t size){

    struct syscall_event *event = data; 

    printf("Received Event!\n");
    printf("pid=%u, syscall_nr=%u, timestamp_ns=%llu\n", event->pid, event->syscall_nr, event->timestamp_ns);

    return 0;
}


int main(int argc, char *argv[])
{
    struct ring_buffer *ring_buffer_monitor = NULL;

    __u32 call_nums[32];
    int count = 0;
    __u32 pid = 0;

    parse_arguements(argc, argv, &pid, call_nums, &count);

    struct monitor *skel;
	int err;
    
    skel = monitor__open_and_load();

    if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton ---> Bad thing\n");
		return 1;
	}
    
    printf("BPF skeleton opened and loaded ---> Good thing\n");

    err = monitor__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton ---> Bad thing\n");
		goto cleanup;
	}


    printf("BPF skeleton was attached ---> Good thing\n");

    int ss = sizeof(__u32);
    int s = sizeof(__u8);
    __u8 value = 1;

    bpf_map__update_elem(skel->maps.tracked_pids, &pid, ss, &value, s, BPF_NOEXIST);

    for(int i = 0; i < count; i++){
        bpf_map__update_elem(skel->maps.watched_syscalls, &call_nums[i], ss, &value, s, BPF_NOEXIST);
    }

    int map_fd = bpf_map__fd(skel->maps.events);

    ring_buffer_monitor = ring_buffer__new(map_fd, callback, NULL, NULL);

    if(!ring_buffer_monitor){
        fprintf(stderr, "Failed to create new ring buffer ---> Bad thing\n");
        goto cleanup;  
    }
    
    while(1){
            ring_buffer__poll(ring_buffer_monitor, 500);  
    }
    
    cleanup:
        if(ring_buffer_monitor){
            ring_buffer__free(ring_buffer_monitor);
        }
        monitor__destroy(skel);
        return -err;
    

    return 0;
}
