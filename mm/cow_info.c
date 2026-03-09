#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/pagewalk.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/pid.h>
#include <linux/rcupdate.h>
#include <linux/mm_types.h>

struct cow_info {
    unsigned long total_cow;
    unsigned long anon_cow;
    unsigned long file_cow;
    unsigned long total_writable;
    unsigned long num_cow_vmas;
    unsigned long cow_fault_count;
};

// context for the walk
struct cow_walk_ctx {
    struct cow_info info;
    bool vma_has_cow;
};

// PTE callback that checks for the 4 cow conditions
static int cow_pte_entry(pte_t *ptep, unsigned long addr,
                         unsigned long end, struct mm_walk *walk)
{
    struct cow_walk_ctx *ctx = walk->private;
    struct vm_area_struct *vma = walk->vma;
    pte_t pte = ptep_get(ptep);
    struct page *page;

    // condition 2: Page must be in physical memory.
    if (!pte_present(pte))
        return 0;

    /* Where total_writable is counted
        This happens before COW checks
        every present page inside writable VMAs
        question, what if the page is empty? 
    */
    ctx->info.total_writable++;

    // condition 3: PTE does NOT have write permission. Kernel removed write permission during fork to detect writes.
    if (pte_write(pte))
        return 0;

    // condition 5: Page is not a special kernel page. Ignore zero page and special mappings.
    page = vm_normal_page(vma, addr, pte);
    if (!page)
        return 0;

    // condition 4: Page is shared (mapped by >1 process). Underlying physical page must have multiple mappings.
    if (folio_mapcount(page_folio(page)) <= 1)
        return 0;

    /*
    Where the page is finally counted as COW
    If all checks pass:
    */
    ctx->info.total_cow++;

    /* Anonymous vs File COW
        vm_file == NULL → anonymous mapping
        vm_file != NULL → file-backed mapping
    */ 
    if (vma->vm_file)
        ctx->info.file_cow++;
    else
        ctx->info.anon_cow++;

    // Where num_cow_vmas is counted
    ctx->vma_has_cow = true;
    return 0;
}

static const struct mm_walk_ops cow_walk_ops = {
    .pte_entry = cow_pte_entry,
};


SYSCALL_DEFINE2(cow_info, pid_t, pid, struct cow_info __user *, info)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    struct cow_walk_ctx ctx = {};
    unsigned long cow_faults;
    int ret = 0;

    if (pid < 0)
        return -EINVAL;

    if (pid == 0) {
        task = current;
        get_task_struct(task);
    } else {
        rcu_read_lock();
        task = find_task_by_vpid(pid);
        if (task)
            get_task_struct(task);
        rcu_read_unlock();

        if (!task)
            return -ESRCH;
    }

    cow_faults = atomic_long_read(&task->cow_fault_count);

    mm = get_task_mm(task);
    put_task_struct(task);

    if (!mm)
        return -EINVAL;

    mmap_read_lock(mm);

    {
        VMA_ITERATOR(vmi, mm, 0);

        for_each_vma(vmi, vma) {
            /*
            condition 1:
            If the VMA was not originally writable → skip the entire region.
            This means every page you scan comes from a writable VMA.
            */
            if (!(vma->vm_flags & VM_WRITE))
                continue;

            ctx.vma_has_cow = false;

            // for every PTE that is found, call the PTE callback function
            ret = walk_page_range(mm, vma->vm_start, vma->vm_end,
                                  &cow_walk_ops, &ctx);
            if (ret)
                break;

            /* Where num_cow_vmas is counted. this VMA contains at least one COW page. 
            question: a vma is a cow if every page is cow or if at least one page is cow? 
            */
            if (ctx.vma_has_cow)
                ctx.info.num_cow_vmas++;
        }
    }

    mmap_read_unlock(mm);
    mmput(mm);

    if (ret)
        return ret;
    
    ctx.info.cow_fault_count = cow_faults;
    
    if (copy_to_user(info, &ctx.info, sizeof(ctx.info)))
        return -EFAULT;

    return 0;
}