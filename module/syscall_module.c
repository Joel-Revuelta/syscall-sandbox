#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
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

static int sandbox_seq_show(struct seq_file *m, void *v)
{
    struct pid_node *pnode;
    struct syscall_node *snode;
    unsigned long flags;

    spin_lock_irqsave(&sandbox_lock, flags);

    seq_printf(m, "BPF map: %s\n", bpf_map_attached ? "attached" : "not attached");
    
    seq_printf(m, "Tracked PIDs (%d):\n", num_tracked_pids);
    list_for_each_entry(pnode, &tracked_pids, list) {
        seq_printf(m, "%d\n", pnode->pid);
    }

    seq_printf(m, "Blocked syscalls (%d):\n", num_blocked_syscalls);
    list_for_each_entry(snode, &blocked_syscalls, list) {
        seq_printf(m, "%d\n", snode->syscall_nr);
    }

    spin_unlock_irqrestore(&sandbox_lock, flags);
    return 0;
}

static int sandbox_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, sandbox_seq_show, NULL);
}

static const struct proc_ops sandbox_proc_ops = {
    .proc_open    = sandbox_proc_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
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
