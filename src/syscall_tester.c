#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s SYSCALL_NR [INTERVAL_SEC]\n", argv[0]);
        fprintf(stderr, "  SYSCALL_NR   Syscall number to invoke\n");
        fprintf(stderr, "  INTERVAL_SEC Seconds between calls (default: 1)\n");
        fprintf(stderr, "\nCommon syscalls:\n");
        fprintf(stderr, "  39  getpid\n");
        fprintf(stderr, "  41  socket\n");
        fprintf(stderr, "  257 openat\n");
        return 1;
    }

    int nr = atoi(argv[1]);
    int interval = (argc > 2) ? atoi(argv[2]) : 1;

    printf("[tester] PID=%d calling syscall %d every %ds\n", getpid(), nr, interval);

    while (1) {
        long ret = syscall(nr);
        printf("[tester] syscall(%d) = %ld\n", nr, ret);
        sleep(interval);
    }

    return 0;
}
