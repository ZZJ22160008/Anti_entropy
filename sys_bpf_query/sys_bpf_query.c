#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/unistd.h>
#include <linux/time.h>
#include <asm/uaccess.h>
#include <linux/sched.h>
#include <linux/kallsyms.h>
#include <linux/bpf.h>
#include <linux/bpf-cgroup.h>
#include <linux/bpf_trace.h>
#include <linux/bpf_lirc.h>
#include <linux/bpf_verifier.h>
#include <linux/btf.h>
#include <linux/syscalls.h>
#include <linux/slab.h>
#include <linux/sched/signal.h>
#include <linux/vmalloc.h>
#include <linux/mmzone.h>
#include <linux/anon_inodes.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/license.h>
#include <linux/filter.h>
#include <linux/idr.h>
#include <linux/cred.h>
#include <linux/timekeeping.h>
#include <linux/ctype.h>
#include <linux/nospec.h>
#include <linux/audit.h>
#include <uapi/linux/btf.h>
#include <linux/pgtable.h>
#include <linux/bpf_lsm.h>
#include <linux/poll.h>
#include <linux/bpf-netns.h>
#include <linux/rcupdate_trace.h>
#include <linux/memcontrol.h>
#include <linux/radix-tree.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/kprobes.h>



#define IS_FD_ARRAY(map) ((map)->map_type == BPF_MAP_TYPE_PERF_EVENT_ARRAY || \
			  (map)->map_type == BPF_MAP_TYPE_CGROUP_ARRAY || \
			  (map)->map_type == BPF_MAP_TYPE_ARRAY_OF_MAPS)
#define IS_FD_PROG_ARRAY(map) ((map)->map_type == BPF_MAP_TYPE_PROG_ARRAY)
#define IS_FD_HASH(map) ((map)->map_type == BPF_MAP_TYPE_HASH_OF_MAPS)
#define IS_FD_MAP(map) (IS_FD_ARRAY(map) || IS_FD_PROG_ARRAY(map) || \
			IS_FD_HASH(map))

#define BPF_OBJ_FLAG_MASK   (BPF_F_RDONLY | BPF_F_WRONLY)

DEFINE_PER_CPU(int, bpf_prog_active);

int sysctl_unprivileged_bpf_disabled __read_mostly =
	IS_BUILTIN(CONFIG_BPF_UNPRIV_DEFAULT_OFF) ? 2 : 0;

static const struct bpf_map_ops * const bpf_map_types[] = {
#define BPF_PROG_TYPE(_id, _name, prog_ctx_type, kern_ctx_type)
#define BPF_MAP_TYPE(_id, _ops) \
	[_id] = &_ops,
#define BPF_LINK_TYPE(_id, _name)
#include <linux/bpf_types.h>
#undef BPF_PROG_TYPE
#undef BPF_MAP_TYPE
#undef BPF_LINK_TYPE
};

#define __NR_syscall 335	/* 系统调用号335 */
const static struct idr *prog_idr = (const struct idr *)0xffffffff94bf74e0;
static unsigned long * syscall_table = (unsigned long *)0xffffffff93e004c0;

unsigned int clear_and_return_cr0(void);
void setback_cr0(unsigned int val);
static int sys_bpf_query(struct pt_regs *regs);

static int orig_cr0;	/* 用来存储cr0寄存器原来的值 */
static int (*anything_saved)(void);	/*定义一个函数指针，用来保存一个系统调用*/

static struct bpf_prog_kstats {
	u64 nsecs;
	u64 cnt;
	u64 misses;
};
 
static void bpf_prog_get_stats(const struct bpf_prog *prog,
			       struct bpf_prog_kstats *stats)
{
	u64 nsecs = 0, cnt = 0, misses = 0;
	int cpu;

	for_each_possible_cpu(cpu) {
		const struct bpf_prog_stats *st;
		unsigned int start;
		u64 tnsecs, tcnt, tmisses;

		st = per_cpu_ptr(prog->stats, cpu);
		do {
			start = u64_stats_fetch_begin_irq(&st->syncp);
			tnsecs = u64_stats_read(&st->nsecs);
			tcnt = u64_stats_read(&st->cnt);
			tmisses = u64_stats_read(&st->misses);
		} while (u64_stats_fetch_retry_irq(&st->syncp, start));
		nsecs += tnsecs;
		cnt += tcnt;
		misses += tmisses;
	}
	stats->nsecs = nsecs;
	stats->cnt = cnt;
	stats->misses = misses;
}


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
static int sys_bpf_query(struct pt_regs *regs)
{
	/*get params pet*/
	unsigned long virt_addr = regs->di;

	struct mm_struct *mm = current->mm;
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	pgd = pgd_offset(mm, virt_addr);
	if (!pgd_present(*pgd))
		printk(KERN_ERR "Failed to get pgd\n");
	p4d = p4d_offset(pgd, virt_addr);
	if (!p4d_present(*p4d))
		printk(KERN_ERR "Failed to get p4d\n");
	pud = pud_offset(p4d, virt_addr);
	if (!pud_present(*pud))
		printk(KERN_ERR "Failed to get pud\n");
	pmd = pmd_offset(pud, virt_addr);
	if (!pmd_present(*pmd))
		printk(KERN_ERR "Failed to get pmd\n");
	pte = pte_offset_map(pmd, virt_addr);
	if (!pte_present(*pte))
		printk(KERN_ERR "Failed to get pte\n");

	pteval_t val = pte_val(*pte);
	printk("pteval = %lx\n", val);
	pteval_t mask = (_AT(pteval_t, 1) << 56);
	if (!(val & mask)) {
		pteval_t new_pteval = val | mask;
		pte_t new_pte = __pte(new_pteval);
		set_pte_atomic(pte, new_pte);
		printk("set success\n");
	}
	
	pte_unmap(pte);


	/* get bpf_prog *prog from prog_idr */
    int __user *uid = (int __user *)regs->si;
    u32 id;
    get_user(id, uid);

	struct bpf_prog *prog;
    if (id >= INT_MAX)
        return -EINVAL;
	prog = idr_get_next(prog_idr, &id);
    if (!prog)
        return -ENOENT;

	int __user *uinfo = (int __user *)regs->di;
	struct bpf_prog_info info;
	u32 info_len = sizeof(info);
	memset(&info, 0, sizeof(info));
	struct bpf_prog_kstats stats;

	/*copy prog info to struct bpf_prog_info*/
	info.id = prog->aux->id;
	info.type = prog->type;
	memcpy(info.name, prog->aux->name, sizeof(prog->aux->name));
	memcpy(info.tag, prog->tag, sizeof(prog->tag));
	info.gpl_compatible = prog->gpl_compatible;

	bpf_prog_get_stats(prog, &stats);
	info.run_time_ns = stats.nsecs;
	info.run_cnt = stats.cnt;
	info.recursion_misses = stats.misses;

	info.load_time = prog->aux->load_time;
	info.created_by_uid = from_kuid_munged(current_user_ns(),
					       prog->aux->user->uid);

	info.xlated_prog_len = bpf_prog_insn_size(prog);
	if (prog->aux->func_cnt) {
		u32 i;
		info.jited_prog_len = 0;
		for (i = 0; i < prog->aux->func_cnt; i++)
			info.jited_prog_len += prog->aux->func[i]->jited_len;
	} else {
		info.jited_prog_len = prog->jited_len;
	}

    /*copt prog info to user*/
	if(copy_to_user(uinfo, &info, info_len) || put_user(id, uid))
		return -EFAULT;
	return 0;
}
NOKPROBE_SYMBOL(sys_bpf_query);

/*模块的初始化函数，模块的入口函数，加载模块*/
static int __init init_addsyscall(void)
{
	printk("My syscall is starting。。。\n");
	anything_saved = (int(*)(void))(syscall_table[__NR_syscall]);	/* 保存原始系统调用 */
	orig_cr0 = clear_and_return_cr0();	/* 设置cr0可更改 */
	syscall_table[__NR_syscall] = (unsigned long)&sys_bpf_query;	/* 更改原始的系统调用服务地址 */
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
