/**
 * bpf_bridge.c
 *
 * Helper tool to bridge eBPF maps with the kernel module.
 *
 * The kernel module needs a file descriptor to the BPF tracked_pids map
 * to update it when processes fork. This tool:
 *   1. Opens the pinned BPF map
 *   2. Passes the fd to the kernel module via /proc
 *   3. Stays running to keep the fd alive
 *
 * Usage:
 *   ./bpf-bridge [--map PATH] [--proc PATH]
 *
 * Example:
 *   # Terminal 1: Start the eBPF monitor (creates and pins the map)
 *   ./sandbox-monitor --watch "39,41,257"
 *
 *   # Terminal 2: Bridge the map to the kernel module
 *   sudo ./bpf-bridge
 *
 *   # Terminal 3: Run sandboxed programs (kernel module now tracks forks)
 *   ./sandbox -c -b 41 -- ./challenge3
 *
 * COMP304 Project 2 — Syscall Sandbox
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <getopt.h>
#include <sys/stat.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define DEFAULT_MAP_PATH  "/sys/fs/bpf/tracked_pids"
#define DEFAULT_PROC_PATH "/proc/syscall_sandbox"

static volatile int running = 1;

static void sigint_handler(int sig)
{
    (void)sig;
    running = 0;
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [options]\n"
        "\n"
        "Bridge eBPF tracked_pids map to the kernel module.\n"
        "\n"
        "This tool opens the pinned BPF map and passes its file descriptor\n"
        "to the kernel module. It must stay running while the integration\n"
        "is active (the fd must remain open).\n"
        "\n"
        "Options:\n"
        "  -m, --map PATH    Path to pinned BPF map (default: %s)\n"
        "  -p, --proc PATH   Path to kernel module proc file (default: %s)\n"
        "  -h, --help        Show this help\n"
        "\n"
        "Workflow:\n"
        "  1. Start sandbox-monitor (creates /sys/fs/bpf/tracked_pids)\n"
        "  2. Load kernel module (creates /proc/syscall_sandbox)\n"
        "  3. Run this tool (bridges them together)\n"
        "  4. Run sandboxed programs with -c flag for fork tracking\n"
        "\n"
        "Example:\n"
        "  # Terminal 1\n"
        "  ./sandbox-monitor --watch \"39,41,257\"\n"
        "\n"
        "  # Terminal 2\n"
        "  sudo insmod module/sandbox_module.ko\n"
        "  sudo ./bpf-bridge\n"
        "\n"
        "  # Terminal 3\n"
        "  ./sandbox -c -b 41 -- ./challenge3\n"
        "\n",
        prog, DEFAULT_MAP_PATH, DEFAULT_PROC_PATH);
}

int main(int argc, char *argv[])
{
    const char *map_path = DEFAULT_MAP_PATH;
    const char *proc_path = DEFAULT_PROC_PATH;
    int map_fd = -1;
    FILE *proc_file = NULL;
    int ret = 1;

    static struct option long_options[] = {
        {"map",  required_argument, 0, 'm'},
        {"proc", required_argument, 0, 'p'},
        {"help", no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "m:p:h", long_options, NULL)) != -1) {
        switch (opt) {
        case 'm':
            map_path = optarg;
            break;
        case 'p':
            proc_path = optarg;
            break;
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    /* Check if map exists */
    struct stat st;
    if (stat(map_path, &st) < 0) {
        fprintf(stderr, "Error: BPF map not found at %s\n", map_path);
        fprintf(stderr, "\nMake sure the eBPF monitor is running first:\n");
        fprintf(stderr, "  ./sandbox-monitor --watch \"39,41,257\"\n\n");
        fprintf(stderr, "The monitor creates and pins the tracked_pids map.\n");
        return 1;
    }

    /* Check if proc file exists */
    if (stat(proc_path, &st) < 0) {
        fprintf(stderr, "Error: Kernel module proc file not found at %s\n", proc_path);
        fprintf(stderr, "\nMake sure the kernel module is loaded:\n");
        fprintf(stderr, "  sudo insmod module/sandbox_module.ko\n");
        return 1;
    }

    /* Open the pinned BPF map */
    printf("[bpf-bridge] Opening BPF map: %s\n", map_path);
    map_fd = bpf_obj_get(map_path);
    if (map_fd < 0) {
        fprintf(stderr, "Error: Failed to open BPF map: %s\n", strerror(errno));
        fprintf(stderr, "\nPossible causes:\n");
        fprintf(stderr, "  - Need root privileges (try sudo)\n");
        fprintf(stderr, "  - Map was unpinned (restart sandbox-monitor)\n");
        return 1;
    }

    printf("[bpf-bridge] Got map fd: %d\n", map_fd);

    /* Pass fd to kernel module */
    printf("[bpf-bridge] Passing fd to kernel module via %s\n", proc_path);
    proc_file = fopen(proc_path, "w");
    if (!proc_file) {
        fprintf(stderr, "Error: Failed to open %s: %s\n", proc_path, strerror(errno));
        fprintf(stderr, "\nNeed root privileges to write to /proc\n");
        goto cleanup;
    }

    if (fprintf(proc_file, "setmap %d\n", map_fd) < 0) {
        fprintf(stderr, "Error: Failed to write setmap command: %s\n", strerror(errno));
        goto cleanup;
    }
    fclose(proc_file);
    proc_file = NULL;

    printf("[bpf-bridge] Integration active!\n");
    printf("[bpf-bridge] The kernel module can now update the eBPF tracked_pids map.\n");
    printf("[bpf-bridge] Press Ctrl+C to disconnect.\n");
    printf("\n");
    printf("[bpf-bridge] IMPORTANT: Keep this tool running!\n");
    printf("[bpf-bridge] If it exits, the fd closes and integration breaks.\n");
    printf("\n");

    /* Set up signal handler */
    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    /* Stay alive to keep the fd open */
    while (running) {
        sleep(1);
    }

    printf("\n[bpf-bridge] Shutting down...\n");
    ret = 0;

cleanup:
    if (proc_file)
        fclose(proc_file);
    if (map_fd >= 0)
        close(map_fd);

    printf("[bpf-bridge] Integration disconnected.\n");
    return ret;
}
