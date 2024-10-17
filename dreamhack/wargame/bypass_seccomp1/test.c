#include <errno.h>
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/fcntl.h>
#include <sys/ptrace.h>
#include <sys/signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <syscall.h>
#include <unistd.h>

void enable_seccomp() {
	scmp_filter_ctx ctx;
	ctx = seccomp_init(SCMP_ACT_ALLOW);
	if (ctx == NULL) {
		printf("seccomp error\n");
		exit(0);
	}

	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(mkdir), 0);

	seccomp_load(ctx);
}

void call_fake_syscall() {
	int rc;
	syscall(SYS_getpid, SYS_mkdir, "hello_world", 0777);
}

int main() {
	// enable_seccomp();

	int pid;
	struct user_regs_struct regs;

	switch ((pid = fork())) {
	case -1:
		perror("Failed to fork.");
		exit(errno);
	case 0:
		ptrace(PTRACE_TRACEME, 0, NULL, NULL);
		kill(getpid(), SIGSTOP);
		call_fake_syscall();
		return 0;
	}

	waitpid(pid, 0, 0);

	while (1) {
		int status;

		ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
		if (waitpid(pid, &status, __WALL) == -1) {
			break;
		}

		if (!(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP)) {
			break;
		}

		ptrace(PTRACE_GETREGS, pid, NULL, &regs);
		printf("##########");
		printf("orig_rax = %lld\n", regs.orig_rax);

		if (regs.rax != -ENOSYS) {
			continue;
		}

		if (regs.orig_rax == SYS_getpid) {
			regs.orig_rax = regs.rdi;
			regs.rdi = regs.rsi;
			regs.rsi = regs.rdx;
			regs.rdx = regs.r10;
			regs.r10 = regs.r8;
			regs.r8 = regs.r9;
			regs.r9 = 0;
			ptrace(PTRACE_SETREGS, pid, NULL, &regs);
		}
	}

	return 0;
}
