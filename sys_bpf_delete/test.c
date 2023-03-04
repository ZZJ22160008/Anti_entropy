#include <syscall.h>
#include <stdio.h>

static int delete_prog(int id)
{
	if(!syscall(336, &id))
		printf("successfully delete %d eBPF program\n", id);
	else
		printf("failed\n");
	return 0;
}

int main(void)
{
	int id;
	printf("input the eBPF program id which you want to delete: ");
	scanf("%d", &id);
	delete_prog(id);
	return 0;
}
