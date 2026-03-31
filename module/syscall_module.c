#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
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

static void add_syscall(int nr) {
    struct syscall_node *node;
    unsigned long flags;

    spin_lock_irqsave(&sandbox_lock, flags);
    list_for_each_entry(node, &blocked_syscalls, list) {
        if (node->syscall_nr == nr) {
            spin_unlock_irqrestore(&sandbox_lock, flags);
            return;
        }
    }
    node = kmalloc(sizeof(*node), GFP_ATOMIC);
    if (!node) {
        spin_unlock_irqrestore(&sandbox_lock, flags);
        return;
    }
    node->syscall_nr = nr;
    list_add_tail(&node->list, &blocked_syscalls);
    num_blocked_syscalls++;
    spin_unlock_irqrestore(&sandbox_lock, flags);
}

static void remove_syscall(int nr) {
    struct syscall_node *node, *tmp;
    unsigned long flags;

    spin_lock_irqsave(&sandbox_lock, flags);
    list_for_each_entry_safe(node, tmp, &blocked_syscalls, list) {
        if (node->syscall_nr == nr) {
            list_del(&node->list);
            kfree(node);
            num_blocked_syscalls--;
            break;
        }
    }
    spin_unlock_irqrestore(&sandbox_lock, flags);
}

static void clear_syscalls(void) {
    struct syscall_node *node, *tmp;
    unsigned long flags;

    spin_lock_irqsave(&sandbox_lock, flags);
    list_for_each_entry_safe(node, tmp, &blocked_syscalls, list) {
        list_del(&node->list);
        kfree(node);
        num_blocked_syscalls--;
    }
    spin_unlock_irqrestore(&sandbox_lock, flags);
}

static void add_pid(pid_t pid) {
    struct pid_node *node;
    unsigned long flags;

    spin_lock_irqsave(&sandbox_lock, flags);
    list_for_each_entry(node, &tracked_pids, list) {
        if (node->pid == pid) {
            spin_unlock_irqrestore(&sandbox_lock, flags);
            return;
        }
    }
    node = kmalloc(sizeof(*node), GFP_ATOMIC);
    if (!node) {
        spin_unlock_irqrestore(&sandbox_lock, flags);
        return;
    }
    node->pid = pid;
    list_add_tail(&node->list, &tracked_pids);
    num_tracked_pids++;
    spin_unlock_irqrestore(&sandbox_lock, flags);
}

static void clear_pids(void) {
    struct pid_node *node, *tmp;
    unsigned long flags;

    spin_lock_irqsave(&sandbox_lock, flags);
    list_for_each_entry_safe(node, tmp, &tracked_pids, list) {
        list_del(&node->list);
        kfree(node);
        num_tracked_pids--;
    }
    spin_unlock_irqrestore(&sandbox_lock, flags);
}

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

static ssize_t sandbox_proc_write(struct file *file, const char __user *ubuf, size_t count, loff_t *ppos)
{
    char buf[64];
    long val;
    size_t len = count;

    if (len >= sizeof(buf))
        len = sizeof(buf) - 1;

    if (copy_from_user(buf, ubuf, len))
        return -EFAULT;

    buf[len] = '\0';

    if (len > 0 && buf[len - 1] == '\n')
        buf[len - 1] = '\0';

    if (!strncmp(buf, "+", 1)) {
        if (kstrtol(buf + 1, 10, &val) == 0)
            add_syscall((int)val);
    } else if (!strncmp(buf, "-", 1)) {
        if (kstrtol(buf + 1, 10, &val) == 0)
            remove_syscall((int)val);
    } else if (!strncmp(buf, "clear", 5)) {
        clear_syscalls();
    } else if (!strncmp(buf, "register ", 9)) {
        if (kstrtol(buf + 9, 10, &val) == 0)
            add_pid((pid_t)val);
    }

    return count;
}

static const struct proc_ops sandbox_proc_ops = {
    .proc_open    = sandbox_proc_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
    .proc_write   = sandbox_proc_write,
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
    clear_syscalls();
    clear_pids();
    pr_info("sandbox: unloaded\n");
}

module_init(sandbox_init);
module_exit(sandbox_exit);
