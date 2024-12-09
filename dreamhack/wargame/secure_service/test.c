#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/prctl.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>

#define DENY_SYSCALL(name)                                                     \
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_##name, 0, 1),                    \
		BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL)
#define MAINTAIN_PROCESS BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW)
#define syscall_nr (offsetof(struct seccomp_data, nr))
#define arch_nr (offsetof(struct seccomp_data, arch))
/* architecture x86_64 */
#define ARCH_NR AUDIT_ARCH_X86_64

int main() {
	struct sock_filter filter[] = {
		/* Validate architecture. */
		/*BPF_STMT(BPF_LD + BPF_W + BPF_ABS, arch_nr),*/
		/*BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ARCH_NR, 1, 0),*/
		/*BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL),*/
		/*Get system call number. */
		/*BPF_STMT(BPF_LD + BPF_W + BPF_ABS, syscall_nr),*/
		/*List allowed syscalls. */
		DENY_SYSCALL(open),
		DENY_SYSCALL(openat),

		/*BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0, 1, 0),*/
		/*BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0, 1, 0),*/
		/*BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0, 1, 0),*/
        MAINTAIN_PROCESS,
		/*BPF_STMT(BPF_LD + BPF_W + BPF_ABS, 0),*/
		/*BPF_STMT(BPF_LD + BPF_W + BPF_ABS, 0),*/
		/*BPF_STMT(BPF_LD + BPF_W + BPF_ABS, 0)*/

	};
	struct sock_fprog prog = {
		.len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
		.filter = filter,
	};

	printf("sizeof sock_fprog: %lx\n", sizeof(prog));
	printf("sizeof sock_filter: %lx\n", sizeof(filter[0]));
	prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
	/*printf("%x\n", SECCOMP_MODE_FILTER);*/
	return 0;
}
