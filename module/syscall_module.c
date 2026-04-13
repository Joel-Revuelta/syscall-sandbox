#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/bpf.h>
#include <linux/file.h>
#include <linux/tracepoint.h>
#include <linux/sched.h>

MODULE_LICENSE("GPL");

static struct proc_dir_entry *proc_entry;

static bool bpf_map_attached = false;
static struct file *sandbox_map_file = NULL;
static struct bpf_map *sandbox_map = NULL;

static struct tracepoint *tp_sched_process_fork = NULL;

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

    // Link tracking to the actual BPF Map data! (If our Map is successfully attached)
    if (bpf_map_attached && sandbox_map && sandbox_map->ops && sandbox_map->ops->map_update_elem) {
        u32 key = pid; // Key is just our int PID
        u8 val = 1;    // Value is essentially a boolean True (1)
        
        // Must read-lock rcu since BPF interacts heavily with rcu locks
        rcu_read_lock();
        sandbox_map->ops->map_update_elem(sandbox_map, (void *)&key, (void *)&val, BPF_ANY);
        rcu_read_unlock();
    }

    spin_unlock_irqrestore(&sandbox_lock, flags);
}

static void clear_pids(void) {
    struct pid_node *node, *tmp;
    unsigned long flags;

    spin_lock_irqsave(&sandbox_lock, flags);
    list_for_each_entry_safe(node, tmp, &tracked_pids, list) {
        list_del(&node->list);

        if (bpf_map_attached && sandbox_map && sandbox_map->ops && sandbox_map->ops->map_delete_elem) {
            u32 key = node->pid;
            rcu_read_lock();
            sandbox_map->ops->map_delete_elem(sandbox_map, (void *)&key);
            rcu_read_unlock();
        }

        kfree(node);
        num_tracked_pids--;
    }
    spin_unlock_irqrestore(&sandbox_lock, flags);
}

static void lookup_tracepoint(struct tracepoint *tp, void *ignore)
{
    // Check if the current tracepoint matches the one we want to hook
    if (!strcmp(tp->name, "sched_process_fork")) {
        tp_sched_process_fork = tp;
    }
}

// This function runs every time a process forks (sched_process_fork tracepoint)
static void probe_fork(void *ignore, struct task_struct *parent, struct task_struct *child)
{
    pid_t parent_pid = parent->pid;
    pid_t child_pid = child->pid;
    struct pid_node *node;
    unsigned long flags;
    bool track_child = false;

    // Check if the parent is in our list of tracked PIDs
    spin_lock_irqsave(&sandbox_lock, flags);
    list_for_each_entry(node, &tracked_pids, list) {
        if (node->pid == parent_pid) {
            track_child = true;
            break;
        }
    }
    spin_unlock_irqrestore(&sandbox_lock, flags);

    // If the parent is tracked, we must also track the newly created child
    if (track_child) {
        add_pid(child_pid);
        pr_info("sandbox: auto-tracking child fork %d from parent %d\n", child_pid, parent_pid);
    }
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
    } else if (!strncmp(buf, "setmap ", 7)) {
        // Parse command: 'setmap <fd>' to attach a userspace eBPF map
        if (kstrtol(buf + 7, 10, &val) == 0) {
            // Get the actual file struct referring to the File Descriptor (val)
            struct file *f = fget((unsigned int)val);
            if (!f) {
                pr_err("sandbox: failed to get bpf map from fd %ld\n", val);
            } else {
                // Clean up any old map reference to avoid memory leaks
                if (sandbox_map_file)
                    fput(sandbox_map_file);
                
                sandbox_map_file = f;
                // Internal BPF map struct is stored inside `private_data`
                sandbox_map = f->private_data;
                bpf_map_attached = true;
                pr_info("sandbox: bpf map attached gracefully via fd %ld\n", val);
            }
        }
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
    int ret;

    // Register the /proc/syscall_sandbox file for Userspace bridging
    proc_entry = proc_create("syscall_sandbox", 0666, NULL, &sandbox_proc_ops);
    if (!proc_entry) {
        pr_err("sandbox: failed to create /proc/syscall_sandbox\n");
        return -ENOMEM;
    }

    // Iterate through ALL kernel tracepoints until we find 'sched_process_fork'
    for_each_kernel_tracepoint(lookup_tracepoint, NULL);
    if (!tp_sched_process_fork) {
        pr_err("sandbox: failed to find sched_process_fork tracepoint\n");
        proc_remove(proc_entry);
        return -ENODEV;
    }

    // Attach our callback `probe_fork` to the located 'sched_process_fork' 
    ret = tracepoint_probe_register(tp_sched_process_fork, probe_fork, NULL);
    if (ret) {
        pr_warn("sandbox: failed to register probe_fork: %d\n", ret);
    }

    pr_info("sandbox: loaded\n");
    return 0;
}

static void __exit sandbox_exit(void)
{
    if (tp_sched_process_fork) {
        tracepoint_probe_unregister(tp_sched_process_fork, probe_fork, NULL);
        tracepoint_synchronize_unregister();
    }

    proc_remove(proc_entry);
    clear_syscalls();
    clear_pids();

    if (sandbox_map_file) {
        fput(sandbox_map_file);
        sandbox_map_file = NULL;
        sandbox_map = NULL;
        bpf_map_attached = false;
    }

    pr_info("sandbox: unloaded\n");
}

module_init(sandbox_init);
module_exit(sandbox_exit);
