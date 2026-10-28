#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <dlfcn.h>
#include <os/log.h>
#include <util.h>
#include "syscall.h"
#include "litehook.h"
#include <libjailbreak/jbclient_mach.h>

extern void __fork(void);

struct fork_pipes {
	int childToParent[2];
	int parentToChild[2];
};

// 关闭已持有的端点，避免失败清理跳过后续描述符。
static void close_pipe_end(int *fd)
{
	if (*fd >= 0) {
		ffsys_close(*fd);
		*fd = -1;
	}
}

// 释放本次 fork 的全部管道，不依赖可被其他线程改写的全局状态。
static void close_pipes(struct fork_pipes *pipes)
{
	close_pipe_end(&pipes->parentToChild[0]);
	close_pipe_end(&pipes->parentToChild[1]);
	close_pipe_end(&pipes->childToParent[0]);
	close_pipe_end(&pipes->childToParent[1]);
}

// 建立握手管道，让断开的写端返回 EPIPE 而不是终止父进程。
static int open_pipes(struct fork_pipes *pipes)
{
	if (pipe(pipes->parentToChild) < 0 || pipe(pipes->childToParent) < 0
		|| fcntl(pipes->parentToChild[1], F_SETNOSIGPIPE, 1) < 0
		|| fcntl(pipes->childToParent[1], F_SETNOSIGPIPE, 1) < 0) {
		int error = errno;
		close_pipes(pipes);
		return error;
	}
	return 0;
}

// 原始读写以负 errno 报错；信号中断需重试，EOF 不能当作放行。
static int handshake_byte(int fd, bool writing)
{
	char msg = ' ';
	ssize_t transferred;
	do {
		transferred = writing ? ffsys_write(fd, &msg, 1) : ffsys_read(fd, &msg, 1);
	} while (transferred == -EINTR);
	if (transferred == 1) return 0;
	if (transferred < 0) return (int)-transferred;
	return transferred == 0 ? EPIPE : EIO;
}

// 子进程必须收到修复完成的字节，才能返回调用方。
static int child_fixup(struct fork_pipes *pipes)
{
	int error = handshake_byte(pipes->childToParent[1], true);
	if (error) return error;
	return handshake_byte(pipes->parentToChild[0], false);
}

// 等待子进程就绪，完成权限修复后才发送放行字节。
static int parent_fixup(struct fork_pipes *pipes, pid_t childPid)
{
	int error = handshake_byte(pipes->childToParent[0], false);
	if (error) return error;
	if (jbclient_mach_fork_fix(childPid) != 0) return EIO;
	return handshake_byte(pipes->parentToChild[1], true);
}

// 握手失败时终止并回收子进程，不让未修复的子进程继续执行。
__attribute__((visibility ("default"))) pid_t forkfix___fork(void)
{
	struct fork_pipes pipes = {{-1, -1}, {-1, -1}};
	int error = open_pipes(&pipes);
	if (error) {
		errno = error;
		return -1;
	}

	pid_t pid = ffsys_fork();
	if (pid < 0) {
		error = errno;
		close_pipes(&pipes);
		errno = error;
		return pid;
	}

	if (pid == 0) {
		close_pipe_end(&pipes.childToParent[0]);
		close_pipe_end(&pipes.parentToChild[1]);
		if (child_fixup(&pipes) != 0) ffsys_exit(127);
	}
	else {
		close_pipe_end(&pipes.childToParent[1]);
		close_pipe_end(&pipes.parentToChild[0]);
		error = parent_fixup(&pipes, pid);
		if (error) {
			kill(pid, SIGKILL);
			close_pipes(&pipes);
			while (waitpid(pid, NULL, 0) < 0 && errno == EINTR) {}
			errno = error;
			return -1;
		}
	}

	close_pipes(&pipes);
	return pid;
}

void apply_fork_hook(void)
{
	static dispatch_once_t onceToken;
	dispatch_once (&onceToken, ^{


/************************* roothide specific **********************/
// find systemhook using <install-name>
void *systemhookHandle = dlopen("systemhook.dylib", RTLD_NOLOAD);
assert(systemhookHandle != NULL);
kern_return_t (*litehook_hook_function)(void *source, void *target) = dlsym(systemhookHandle, "litehook_hook_function");
assert(litehook_hook_function != NULL);
/************************* roothide specific **********************/


		litehook_hook_function((void *)__fork, (void *)forkfix___fork);
	});
}

__attribute__((constructor)) static void initializer(void)
{
	apply_fork_hook();
}
