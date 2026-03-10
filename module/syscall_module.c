#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");

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
