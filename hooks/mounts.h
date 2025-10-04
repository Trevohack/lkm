#ifndef MOUNTS_H
#define MOUNTS_H

#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/sched.h>

typedef asmlinkage long (*orig_mount_t)(const char __user *,
                                        const char __user *,
                                        const char __user *,
                                        unsigned long,
                                        void __user *);
static orig_mount_t orig_mount = NULL;

typedef asmlinkage long (*orig_move_mount_t)(int,
                                             const char __user *,
                                             int,
                                             const char __user *,
                                             unsigned long);
static orig_move_mount_t orig_move_mount = NULL;

asmlinkage long hook_mount(const char __user *dev_name,
                           const char __user *dir_name,
                           const char __user *type,
                           unsigned long flags,
                           void __user *data)
{
    char kdev[128] = "";
    char kdir[128] = "";

    if (dev_name && strncpy_from_user(kdev, dev_name, sizeof(kdev) - 1) < 0)
        kdev[0] = '\0';

    if (dir_name && strncpy_from_user(kdir, dir_name, sizeof(kdir) - 1) < 0)
        kdir[0] = '\0';

		printk(KERN_INFO "====================================================\n");
		printk(KERN_INFO "HACKVERSE HOOKED MOVE_MOUNT\n");
		printk(KERN_INFO "@0xTrevo @Devil0x1\n");
		printk(KERN_INFO "====================================================");

    return -EPERM;
}

asmlinkage long hook_move_mount(int from_dfd,
                                const char __user *from_pathname,
                                int to_dfd,
                                const char __user *to_pathname,
                                unsigned long flags)
{
    char from_k[256] = "";
    char to_k[256] = "";

    if (from_pathname && strncpy_from_user(from_k, from_pathname, sizeof(from_k) - 1) < 0)
        from_k[0] = '\0';

    if (to_pathname && strncpy_from_user(to_k, to_pathname, sizeof(to_k) - 1) < 0)
        to_k[0] = '\0';

    printk(KERN_INFO "====================================================\n");
    printk(KERN_INFO "HACKVERSE HOOKED MOVE_MOUNT\n");
    printk(KERN_INFO "@0xTrevo @Devil0x1\n");
    printk(KERN_INFO "====================================================");
    

    return -EPERM;
}

#endif 
