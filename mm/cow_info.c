#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>

struct cow_info {
    unsigned long total_cow;
    unsigned long anon_cow;
    unsigned long file_cow;
    unsigned long total_writable;
    unsigned long num_cow_vmas;
    unsigned long cow_fault_count;
};

SYSCALL_DEFINE2(cow_info, pid_t, pid, struct cow_info __user *, info)
{
    return 0;
}
