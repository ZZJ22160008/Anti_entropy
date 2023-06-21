#include <syscall.h>
#include <linux/kernel.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <dirent.h>
#include <err.h>
#include <linux/perf_event.h>
#include <linux/bpf.h>
#include <linux/btf.h>

#define true 1
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

const char * const prog_type_name[] = {
	[BPF_PROG_TYPE_UNSPEC]			= "unspec",
	[BPF_PROG_TYPE_SOCKET_FILTER]		= "socket_filter",
	[BPF_PROG_TYPE_KPROBE]			= "kprobe",
	[BPF_PROG_TYPE_SCHED_CLS]		= "sched_cls",
	[BPF_PROG_TYPE_SCHED_ACT]		= "sched_act",
	[BPF_PROG_TYPE_TRACEPOINT]		= "tracepoint",
	[BPF_PROG_TYPE_XDP]			= "xdp",
	[BPF_PROG_TYPE_PERF_EVENT]		= "perf_event",
	[BPF_PROG_TYPE_CGROUP_SKB]		= "cgroup_skb",
	[BPF_PROG_TYPE_CGROUP_SOCK]		= "cgroup_sock",
	[BPF_PROG_TYPE_LWT_IN]			= "lwt_in",
	[BPF_PROG_TYPE_LWT_OUT]			= "lwt_out",
	[BPF_PROG_TYPE_LWT_XMIT]		= "lwt_xmit",
	[BPF_PROG_TYPE_SOCK_OPS]		= "sock_ops",
	[BPF_PROG_TYPE_SK_SKB]			= "sk_skb",
	[BPF_PROG_TYPE_CGROUP_DEVICE]		= "cgroup_device",
	[BPF_PROG_TYPE_SK_MSG]			= "sk_msg",
	[BPF_PROG_TYPE_RAW_TRACEPOINT]		= "raw_tracepoint",
	[BPF_PROG_TYPE_CGROUP_SOCK_ADDR]	= "cgroup_sock_addr",
	[BPF_PROG_TYPE_LWT_SEG6LOCAL]		= "lwt_seg6local",
	[BPF_PROG_TYPE_LIRC_MODE2]		= "lirc_mode2",
	[BPF_PROG_TYPE_SK_REUSEPORT]		= "sk_reuseport",
	[BPF_PROG_TYPE_FLOW_DISSECTOR]		= "flow_dissector",
	[BPF_PROG_TYPE_CGROUP_SYSCTL]		= "cgroup_sysctl",
	[BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE]	= "raw_tracepoint_writable",
	[BPF_PROG_TYPE_CGROUP_SOCKOPT]		= "cgroup_sockopt",
	[BPF_PROG_TYPE_TRACING]			= "tracing",
	[BPF_PROG_TYPE_STRUCT_OPS]		= "struct_ops",
	[BPF_PROG_TYPE_EXT]			= "ext",
	[BPF_PROG_TYPE_LSM]			= "lsm",
	[BPF_PROG_TYPE_SK_LOOKUP]		= "sk_lookup",
};


/*define whitelist*/
static int prog_type_whitelist[] = {8, 15};
static int prog_id_whitelist[] = {3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 26, 27, 33, 34};


void fprint_hex(FILE *f, void *arg, unsigned int n, const char *sep)
{
	unsigned char *data = arg;
	unsigned int i;

	for (i = 0; i < n; i++) {
		const char *pfx = "";

		if (!i)
			/* nothing */;
		else if (!(i % 16))
			fprintf(f, "\n");
		else if (!(i % 8))
			fprintf(f, "  ");
		else
			pfx = sep;

		fprintf(f, "%s%02hhx", i ? pfx : "", data[i]);
	}
}

static void print_boot_time(__u64 nsecs, char *buf, unsigned int size)
{
	struct timespec real_time_ts, boot_time_ts;
	time_t wallclock_secs;
	struct tm load_tm;

	buf[--size] = '\0';

	if (clock_gettime(CLOCK_REALTIME, &real_time_ts) ||
	    clock_gettime(CLOCK_BOOTTIME, &boot_time_ts)) {
		perror("Can't read clocks");
		snprintf(buf, size, "%llu", nsecs / 1000000000);
		return;
	}

	wallclock_secs = (real_time_ts.tv_sec - boot_time_ts.tv_sec) +
		(real_time_ts.tv_nsec - boot_time_ts.tv_nsec + nsecs) /
		1000000000;


	if (!localtime_r(&wallclock_secs, &load_tm)) {
		snprintf(buf, size, "%llu", nsecs / 1000000000);
		return;
	}

	strftime(buf, size, "%FT%T%z", &load_tm);
}

static __attribute__((noclone)) void print_prog_plain(struct bpf_prog_info *info)
{
	printf("%u: ", info->id);
	if (info->type < ARRAY_SIZE(prog_type_name))
		printf("%s  ", prog_type_name[info->type]);
	else
		printf("type %u  ", info->type);

	if (*info->name)
		printf("name %s  ", info->name);

	printf("tag ");
	fprint_hex(stdout, info->tag, BPF_TAG_SIZE, "");
	printf("%s", info->gpl_compatible ? "  gpl" : "");
	if (info->run_time_ns)
		printf(" run_time_ns %lld run_cnt %lld",
		       info->run_time_ns, info->run_cnt);
	if (info->recursion_misses)
		printf(" recursion_misses %lld", info->recursion_misses);
	printf("\n");

	if (info->load_time) {
		char buf[32];

		print_boot_time(info->load_time, buf, sizeof(buf));

		/* Piggy back on load_time, since 0 uid is a valid one */
		printf("\tloaded_at %s  uid %u\n", buf, info->created_by_uid);
	}

	printf("\txlated %uB", info->xlated_prog_len);

	if (info->jited_prog_len)
		printf("  jited %uB", info->jited_prog_len);
	else
		printf("  not jited");

	printf("\n");
}

static int filter_prog_by_type(struct bpf_prog_info info, int whitelist[], int size){
	int count = 0;
	for(int i = 0; i < size; i++){
		if ((int) info.type == whitelist[i])
			count++;
	}
	return count;
}

static int filter_prog_by_id(struct bpf_prog_info info, int whitelist[], int size){
	int count = 0;
	for(int i = 0; i < size; i++){
		if ((int) info.id == whitelist[i])
			count++;
	}
	return count;
}

static int delete_prog(int id)
{
	if(!syscall(336, &id)){
		printf("successfully delete %d eBPF program\n", id);
		printf("\n");
	}
	else
		printf("failed\n");
	return 0;
}

static void show_prog(void)
{
	__u32 id = 0;
	struct bpf_prog_info info = {};
	int len = sizeof(info);
	printf("%d\n", len);
	int err;


	while (true){
		if (err = syscall(335, &info, &id, len)){
			break;
		}
           
        id++;
		print_prog_plain(&info);

		if(filter_prog_by_type(info, prog_type_whitelist, sizeof(prog_type_whitelist)) 
		&& filter_prog_by_id(info, prog_id_whitelist, sizeof(prog_id_whitelist)))
			continue;
		else
			delete_prog(info.id);
	}
}

int main(void)
{
	int id;
	show_prog();
	return 0;
}
