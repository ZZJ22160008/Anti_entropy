#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/unistd.h>
#include <linux/time.h>
#include <asm/uaccess.h>
#include <linux/sched.h>
#include <linux/kallsyms.h>
#include <linux/bpf.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/fdtable.h>
#include <linux/idr.h>
#include <linux/filter.h>
#include <linux/kprobes.h>


#define __NR_syscall 336	/* 系统调用号336 */
const static struct idr *prog_idr = (const struct idr *)0xffffffff901f74e0;
const static struct idr *link_idr = (const struct idr *)0xffffffff901f74a0;
static unsigned long * syscall_table = (unsigned long *)0xffffffff8f4004c0;

unsigned int clear_and_return_cr0(void);
void setback_cr0(unsigned int val);
static int sys_bpf_delete(struct pt_regs *regs);

static int orig_cr0;	/* 用来存储cr0寄存器原来的值 */
static int (*anything_saved)(void);	/*定义一个函数指针，用来保存一个系统调用*/
/*
 * 设置cr0寄存器的第17位为0
 */
unsigned int clear_and_return_cr0(void)	
{
   	unsigned int cr0 = 0;
   	unsigned int ret;
    /* 前者用在32位系统。后者用在64位系统，本系统64位 */
    //asm volatile ("movl %%cr0, %%eax" : "=a"(cr0));	
   	asm volatile ("movq %%cr0, %%rax" : "=a"(cr0));	/* 将cr0寄存器的值移动到rax寄存器中，同时输出到cr0变量中 */
    ret = cr0;
	cr0 &= 0xfffeffff;	/* 将cr0变量值中的第17位清0，将修改后的值写入cr0寄存器 */
	//asm volatile ("movl %%eax, %%cr0" :: "a"(cr0));
	asm volatile ("movq %%rax, %%cr0" :: "a"(cr0));	/* 读取cr0的值到rax寄存器，再将rax寄存器的值放入cr0中 */
	return ret;
}

/* 读取val的值到rax寄存器，再将rax寄存器的值放入cr0中 */
void setback_cr0(unsigned int val)
{	

	//asm volatile ("movl %%eax, %%cr0" :: "a"(val));
	asm volatile ("movq %%rax, %%cr0" :: "a"(val));
}

/* 添加自己的系统调用函数 */
static int sys_bpf_delete(struct pt_regs *regs){

    /* get bpf_prog *prog from prog_idr */
    int __user *uid = (int __user *)regs->di;
    u32 id;
    get_user(id, uid);

    struct bpf_prog *prog;
    if (id >= INT_MAX)
        return -EINVAL;
    prog = idr_get_next(prog_idr, &id);
    if (!prog)
        return -ENOENT;

    /*get bpf_link *link by prog*/
    u32 link_id = 0;
    struct bpf_link *link;
    while (link = idr_get_next(link_idr, &link_id)) {
	if (link->prog == prog) break;
	link_id++;
    }

    /*traverse current open files*/
    struct task_struct *task;
    struct files_struct *files;
    struct fdtable *fdt;
    struct file *file;
    int i, j;

    rcu_read_lock();
    for_each_process(task) {
	//get open file table
	files = task->files;
	if (!files) {
            printk(KERN_ERR "No files found for process with pid %d\n", task->pid);
            return -EINVAL;
        }
	// 获取进程的文件描述符表
    	fdt = files->fdt;
        
	// 遍历文件描述符表
    	for (i = 0; i < fdt->max_fds; i++) {
            file = fdt->fd[i];
		if (file) {
 		    if (file->private_data == prog) {
			// 关闭文件
        		filp_close(file, files);
        		fdt->fd[i] = NULL;
			}
		    for (j = 0; j < prog->aux->used_map_cnt; j++) {
			if (file->private_data == prog->aux->used_maps[j]) {
			    // 关闭文件
        		    filp_close(file, files);
        		    fdt->fd[i] = NULL;
			}
		    }
		    if (file->private_data == link) {
			// 关闭文件
        		filp_close(file, files);
        		fdt->fd[i] = NULL;
		    }
		    // kill the process
 		    // if (file->private_data == prog) {
		    // 	printk("fd = %d\n", i);
		    // 	send_sig(SIGKILL, task, 1);
		    // }
	    }
    	}
    }
    rcu_read_unlock();
    return 0;
}
NOKPROBE_SYMBOL(sys_bpf_delete);

/*模块的初始化函数，模块的入口函数，加载模块*/
static int __init init_addsyscall(void)
{
	printk("My syscall is starting。。。\n");
	anything_saved = (int(*)(void))(syscall_table[__NR_syscall]);	/* 保存原始系统调用 */
	orig_cr0 = clear_and_return_cr0();	/* 设置cr0可更改 */
	syscall_table[__NR_syscall] = (unsigned long)&sys_bpf_delete;	/* 更改原始的系统调用服务地址 */
	setback_cr0(orig_cr0);	/* 设置为原始的只读cr0 */
	return 0;
}

/*出口函数，卸载模块*/
static void __exit exit_addsyscall(void)
{
 	orig_cr0 = clear_and_return_cr0();	/* 设置cr0中对syscall_table的更改权限 */
    syscall_table[__NR_syscall] = (unsigned long)anything_saved;	/* 设置cr0可更改 */
    setback_cr0(orig_cr0);	/* 恢复原有的中断向量表中的函数指针的值 */
   	printk("My syscall exit....\n");	/* 恢复原有的cr0的值 */
}

module_init(init_addsyscall);
module_exit(exit_addsyscall);
MODULE_LICENSE("GPL");
