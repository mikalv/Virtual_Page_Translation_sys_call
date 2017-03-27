
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



































/* P2 Step1 


#include <linux/syscalls.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/tty.h>
#include "syscall_header.h"
#include <linux/slab.h>
#define PROCESS_NUM 200

asmlinkage long sys_my_syscall(void* dest)
{
	struct process* proc_name;
	struct task_struct *task;
	struct task_struct *curr=get_current();
	int i , ret;
	struct process* destination;
	cputime_t utime=0, stime=0;
	int ts=0,ppp=0;
	ppp=curr->parent->parent->pid;
	printk(KERN_ALERT "--------PS -e Starts Here-----%d\n",ppp);
	proc_name = kmalloc(PROCESS_NUM * sizeof(struct process), GFP_KERNEL);
	destination = (struct process*)dest;
	ret = 0;
	i = 0;
	for_each_process(task){	

		utime=task->signal->utime;
		stime=task->signal->stime;
		thread_group_cputime_adjusted(task,&utime,&stime);
		ts=(utime + stime)/HZ;
		
		strcpy(proc_name[i].process_name,task->comm);
		proc_name[i].pid = task->pid;
		proc_name[i].time_sec = ts;
		
		if(task->signal->tty != NULL){
			printk("[%d]\t%s\t%i\t%s\n",task->pid,task->signal->tty->name,ts,task->comm);
			strcpy(proc_name[i].tty,task->signal->tty->name);
		}
		else{
			printk("[%d]\t?\t%i\t%s\n",task->pid,ts,task->comm);
			strcpy(proc_name[i].tty,"?");
		}
		
		i++;
		if (i == PROCESS_NUM)
			break;
	}

	if(i!=PROCESS_NUM){
		strcpy(proc_name[i].tty,"NULL");
		strcpy(proc_name[i].process_name,"NULL");
		proc_name[i].pid = -1;
		proc_name[i].time_sec = 0;
	} 
    ret =  copy_to_user(destination,proc_name,(PROCESS_NUM * sizeof(struct process) ));
    kfree(proc_name);
    return ret;
}

*/
