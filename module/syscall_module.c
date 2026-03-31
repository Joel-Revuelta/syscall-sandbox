#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/list.h>
#include <linux/spinlock.h>

MODULE_LICENSE("GPL");

static struct proc_dir_entry *proc_entry;

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

static const struct proc_ops sandbox_proc_ops = {
};

static int __init sandbox_init(void)
{
    proc_entry = proc_create("syscall_sandbox", 0666, NULL, &sandbox_proc_ops);
    if (!proc_entry) {
        pr_err("sandbox: failed to create /proc/syscall_sandbox\n");
        return -ENOMEM;
    }

    pr_info("sandbox: loaded\n");
    return 0;
}

static void __exit sandbox_exit(void)
{
    proc_remove(proc_entry);
    pr_info("sandbox: unloaded\n");
}

module_init(sandbox_init);
module_exit(sandbox_exit);
