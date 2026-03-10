#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

int main(int argc, char *argv[])
{
    const char *obj_path = "ebpf/monitor.bpf.o";

    if (argc > 1)
        obj_path = argv[1];

    printf("[monitor] loading %s\n", obj_path);

    return 0;
}
