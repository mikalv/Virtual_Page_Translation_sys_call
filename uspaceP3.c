#include <linux/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include "syscall_headerP3.h"
#include <string.h>

#define __NR_my_syscall 359

int main(char argc, char**argv)
{
	struct Table T1;
	int ret = 0;
	unsigned long vadd;
	char* e;
	if (argc !=3){
		printf("Incoorect number of arguments\n");
		return -1;	
	}
	
	vadd = (unsigned long)strtoull(argv[2], &e, 16);
	ret = syscall(__NR_my_syscall,atoi(argv[1]),strtoull(argv[2], &e, 16),&T1);
	
	if(!T1.flg){
		printf("\tvirtual address: 0x%08lx, vfn: %lu, pfn: %llu phys_addr:0x%08llx \n", vadd, vadd>>12, (T1.addr & 0x00000000FFFFFFFF)>>12, T1.addr & 0x00000000FFFFFFFF); 
	}
	else{
		printf("\tvirtual address: 0x%08llx, vfn: %llu, swap_id: %llu, swap_offset: %llu \n", strtoull(argv[2], &e, 16), (strtoull(argv[2], &e, 16))>>12, T1.addr, T1.addr>>5 ); 
	}
	return 0;
}

