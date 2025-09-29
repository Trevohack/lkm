#ifndef IOCTL_H
#define IOCTL_H

#include "../include/headers.h"

static asmlinkage long (*orig_ioctl)(const struct pt_regs *regs);

// Common IOCTL commands that attackers might use for reconnaissance
#define SIOCGIFCONF     0x8912  // Get interface configuration
#define SIOCGIFFLAGS    0x8913  // Get interface flags  
#define SIOCGIFADDR     0x8915  // Get interface address
#define SIOCGIFNETMASK  0x891b  // Get network mask
#define SIOCGIFHWADDR   0x8927  // Get hardware address
#define TCGETS          0x5401  // Terminal control get
#define TCSETS          0x5402  // Terminal control set
#define TIOCGWINSZ      0x5413  // Get window size
#define TIOCSWINSZ      0x5414  // Set window size

// Hook for ioctl syscall - block dangerous operations
static asmlinkage long hooked_ioctl(const struct pt_regs *regs) {
    unsigned int fd = (unsigned int)regs->di;
    unsigned int cmd = (unsigned int)regs->si;
    struct file *file;
    
    // Get file structure
    file = fget(fd);
    if (file) {
        // Block network interface enumeration attempts
        if (cmd == SIOCGIFCONF || cmd == SIOCGIFFLAGS || 
            cmd == SIOCGIFADDR || cmd == SIOCGIFNETMASK ||
            cmd == SIOCGIFHWADDR) {
            
            // Check if this is a socket file descriptor
            if (file->f_op && file->f_op->unlocked_ioctl) {
                fput(file);
                printk(KERN_DEBUG "[BlueDefense] Blocked network enumeration ioctl: 0x%x from PID %d\n", 
                       cmd, current->pid);
                return -EPERM; // Block network enumeration
            }
        }
        
        // Block terminal manipulation on protected TTYs
        if (cmd == TCGETS || cmd == TCSETS || cmd == TIOCGWINSZ || cmd == TIOCSWINSZ) {
            // Check if this is a TTY that should be protected
            if (file->f_path.dentry && file->f_path.dentry->d_name.name) {
                const char *name = file->f_path.dentry->d_name.name;
                
                // Protect specific terminals (pts/0, pts/1 commonly used by blue team)
                if (strstr(name, "pts") && 
                    (strstr(name, "0") || strstr(name, "1") || strstr(name, "console"))) {
                    
                    // Allow if coming from root or specific UIDs
                    if (current_uid().val != 0 && 
                        current_uid().val != 1001 && // blueteam user
                        current_uid().val != 1002) { // forensic user
                        
                        fput(file);
                        printk(KERN_DEBUG "[BlueDefense] Blocked TTY manipulation on %s from UID %d\n", 
                               name, current_uid().val);
                        return -EACCES;
                    }
                }
            }
        }
        
        // Block debugger-related ioctls that could interfere with our hooks
        if (cmd == PTRACE_TRACEME || cmd == PTRACE_ATTACH || 
            cmd == PTRACE_DETACH || cmd == PTRACE_PEEKTEXT) {
            
            fput(file);
            printk(KERN_DEBUG "[BlueDefense] Blocked potential debugger ioctl: 0x%x\n", cmd);
            return -EPERM;
        }
        
        fput(file);
    }
    
    // Allow other ioctl operations
    return orig_ioctl(regs);
}

#endif // IOCTL_H
