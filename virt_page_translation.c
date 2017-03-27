
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/tty.h>
#include <linux/syscalls.h>
#include "syscall_headerP3.h"
#include <linux/slab.h>
//#include <asm/pgtable.h>
//#include <linux/highmem.h>
#include <linux/spinlock.h>

asmlinkage void sys_my_syscall(int pid, unsigned long long virtual_addr, void* dest)
{
    struct Table T1;
    
    struct task_struct *task;
	struct mm_struct *mm_task=NULL;
	
	pgd_t *pgd_entry;
	pud_t *pud_entry;
	pmd_t *pmd_entry;
	pte_t *pte_entry;
	int ret;

	//Specify the virtual address that needs translation. Will take it as argument when implementing  system call.
	//unsigned long add_user =  0xbfd7a000;
	unsigned long long add_user =  virtual_addr;
	int PID_USER = pid;
	unsigned long long vfn;
	rwlock_t rd_lock;
	rwlock_init(&rd_lock);
	T1.flg = 0;
    T1.addr = 0;

    printk(KERN_ALERT "--------Function Starts Here-----\n");

	//Go through the task list to get task_struct for required PID
	read_lock(&rd_lock);
	for_each_process(task)
	{
		if(task->pid == PID_USER)
		{	mm_task = task->mm;	
			break;
		}
	}
	read_unlock(&rd_lock);
	
	if(mm_task == NULL)
	{	
		ret = copy_to_user(dest, &T1, sizeof(T1));
		return;	

	}
	spin_lock(&mm_task->page_table_lock);
	//get pgd from mm_struct 
	pgd_entry = pgd_offset(mm_task,add_user);
	printk(KERN_ALERT "PGD FOUND %llu\n",(unsigned long long)pgd_val(*pgd_entry));

	pud_entry = pud_offset(pgd_entry,add_user);
	if(pud_none(*pud_entry))
	{	
		printk(KERN_ALERT "PUD is NULL\n");
		ret = copy_to_user(dest, &T1, sizeof(T1));
		spin_unlock(&mm_task->page_table_lock);
		return;
	}
	printk(KERN_ALERT "PUD FOUND %llu\n",(unsigned long long)pud_val(*pud_entry));

	pmd_entry = pmd_offset(pud_entry,add_user);
	if(pmd_none(*pmd_entry))
	{	
		printk(KERN_ALERT "PMD is NULL\n");
		ret = copy_to_user(dest, &T1, sizeof(T1));
		spin_unlock(&mm_task->page_table_lock);
		return;
	}

	printk(KERN_ALERT "PMD FOUND %llu\n",(unsigned long long)pmd_val(*pmd_entry));


	pte_entry = pte_offset_kernel(pmd_entry,add_user);
	if(pte_none(*pte_entry))
	{	printk(KERN_ALERT "PTE is NULL\n");
		ret = copy_to_user(dest, &T1, sizeof(T1));
		spin_unlock(&mm_task->page_table_lock);	
		return;
	}

	if(pte_present(*pte_entry))
	{
		vfn = ((unsigned long long)pte_val(*pte_entry))>>12;
		T1.addr = (vfn <<12)|(add_user & 0x00000FFF);
		T1.flg = 0;
		ret = copy_to_user(dest, &T1, sizeof(T1));			
	}
	else
	{
		printk(KERN_ALERT "Swapped\n");
		T1.addr = ((unsigned long long)pte_val(*pte_entry))>>32;
		T1.flg = 1;
		ret = copy_to_user(dest, &T1, sizeof(T1));	
	}
	
	spin_unlock(&mm_task->page_table_lock);
	return;
}
