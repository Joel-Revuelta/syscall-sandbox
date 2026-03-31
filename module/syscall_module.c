#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/spinlock.h>

MODULE_LICENSE("GPL");

static bool bpf_map_attached = false;

struct pid_node {
    pid_t pid;
    struct list_head list;
};

struct syscall_node {
    int syscall_nr;
    struct list_head list;
};

static LIST_HEAD(tracked_pids);
static LIST_HEAD(blocked_syscalls);

static int num_tracked_pids = 0;
static int num_blocked_syscalls = 0;

static DEFINE_SPINLOCK(sandbox_lock);

static int __init sandbox_init(void)
{
    pr_info("sandbox: loaded\n");
    return 0;
}

static void __exit sandbox_exit(void)
{
    pr_info("sandbox: unloaded\n");
}

module_init(sandbox_init);
module_exit(sandbox_exit);
