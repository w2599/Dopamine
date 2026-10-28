#!/usr/bin/env python3
"""使用真实 forkfix 函数、Darwin ARM64 系统调用及管道验证握手。"""

from pathlib import Path
import os
import platform
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]

STUBS = r"""
#include <assert.h>
#include <stdbool.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/time.h>
ssize_t ffsys_read(int, void *, size_t);
ssize_t ffsys_write(int, const void *, size_t);
int ffsys_close(int);
__attribute__((noreturn)) void ffsys_exit(int);
static int mock_read[8], mock_write[8], read_count, write_count, read_index, write_index;
static int patch_result, patch_calls, pipe_calls, fail_pipe, fail_fork, fail_child;
static pid_t last_child;
/* 默认调用真实原始系统调用，仅指定用例注入错误序列。 */
static ssize_t test_read(int fd, void *data, size_t size) {
    if (read_index < read_count) return mock_read[read_index++];
    return ffsys_read(fd, data, size);
}
/* 保留原始负 errno 约定，不能以主机 libc 桩掩盖汇编错误。 */
static ssize_t test_write(int fd, const void *data, size_t size) {
    if (write_index < write_count) return mock_write[write_index++];
    return ffsys_write(fd, data, size);
}
/* 对失败前已打开的管道做资源回收验证。 */
static int test_pipe(int fds[2]) {
    if (++pipe_calls == fail_pipe) { errno = EMFILE; return -1; }
    return pipe(fds);
}
/* 使用真实 fork，失败分支单独注入。 */
static pid_t ffsys_fork(void) {
    if (fail_fork) { errno = EAGAIN; return -1; }
    pid_t pid = fork();
    if (pid == 0 && fail_child) ffsys_exit(127);
    if (pid > 0) last_child = pid;
    return pid;
}
/* 无设备操作，只记录是否在正确阶段请求权限修复。 */
static int64_t jbclient_mach_fork_fix(pid_t pid) { patch_calls++; return patch_result; }
#define ffsys_read test_read
#define ffsys_write test_write
#define pipe test_pipe
"""

CASES = r"""
#undef ffsys_read
#undef ffsys_write
#undef pipe
static volatile sig_atomic_t signals;
/* 信号只记录到达，故意不安装 SA_RESTART。 */
static void caught(int signal) { signals++; }
/* 清空注入状态，使后续用例走真实系统调用。 */
static void reset(void) {
    read_count = write_count = read_index = write_index = 0;
    patch_result = patch_calls = pipe_calls = fail_pipe = fail_fork = fail_child = 0;
}
/* 统计进程打开的描述符，确认失败路径没有积累资源。 */
static int fd_count(void) {
    int count = 0;
    for (int fd = 0; fd < 1024; fd++) if (fcntl(fd, F_GETFD) != -1) count++;
    return count;
}
/* 验证真实子进程不会被中断的 read 提前放行。 */
static void signal_case(void) {
    struct fork_pipes pipes = {{-1,-1},{-1,-1}};
    assert(open_pipes(&pipes) == 0);
    pid_t child = fork();
    assert(child >= 0);
    if (!child) {
        close_pipe_end(&pipes.childToParent[0]);
        close_pipe_end(&pipes.parentToChild[1]);
        struct sigaction action = {.sa_handler = caught};
        sigemptyset(&action.sa_mask);
        sigaction(SIGALRM, &action, NULL);
        ualarm(20000, 0);
        int ret = child_fixup(&pipes);
        ffsys_exit(ret == 0 && signals == 1 ? 0 : 2);
    }
    close_pipe_end(&pipes.childToParent[1]);
    close_pipe_end(&pipes.parentToChild[0]);
    assert(handshake_byte(pipes.childToParent[0], false) == 0);
    usleep(100000);
    int status;
    assert(waitpid(child, &status, WNOHANG) == 0);
    assert(handshake_byte(pipes.parentToChild[1], true) == 0);
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    close_pipes(&pipes);
}
/* 在不同失败点验证握手结果、子进程回收和 fd 清理。 */
int main(void) {
    alarm(10);
    char byte;
    assert(ffsys_read(-1, &byte, 1) == -EBADF);
    assert(ffsys_write(-1, &byte, 1) == -EBADF);
    mock_read[0] = -EINTR; mock_read[1] = -EINTR; mock_read[2] = 1; read_count = 3;
    assert(handshake_byte(-1, false) == 0 && read_index == 3);
    mock_write[0] = -EINTR; mock_write[1] = 1; write_count = 2;
    assert(handshake_byte(-1, true) == 0 && write_index == 2);
    reset(); mock_read[0] = 0; read_count = 1;
    assert(handshake_byte(-1, false) == EPIPE);
    reset(); mock_write[0] = -EIO; write_count = 1;
    struct fork_pipes dummy = {{-1,-1},{-1,-1}};
    assert(child_fixup(&dummy) == EIO && read_index == 0);
    reset(); mock_read[0] = -EBADF; read_count = 1;
    assert(parent_fixup(&dummy, 123) == EBADF && patch_calls == 0 && write_index == 0);
    reset(); mock_read[0] = 1; read_count = 1; patch_result = -1;
    assert(parent_fixup(&dummy, 123) == EIO && patch_calls == 1 && write_index == 0);
    reset();
    int baseline = fd_count();
    for (fail_pipe = 1; fail_pipe <= 2; fail_pipe++) {
        pipe_calls = 0;
        assert(forkfix___fork() == -1 && errno == EMFILE);
        assert(fd_count() == baseline);
    }
    reset(); fail_fork = 1;
    assert(forkfix___fork() == -1 && errno == EAGAIN);
    assert(fd_count() == baseline);
    reset();
    struct fork_pipes pipes = {{-1,-1},{-1,-1}};
    assert(open_pipes(&pipes) == 0);
    assert(fcntl(pipes.childToParent[1], F_GETNOSIGPIPE) == 1);
    close_pipe_end(&pipes.childToParent[0]);
    assert(handshake_byte(pipes.childToParent[1], true) == EPIPE);
    close_pipe_end(&pipes.parentToChild[1]);
    assert(handshake_byte(pipes.parentToChild[0], false) == EPIPE);
    close_pipes(&pipes);
    signal_case();
    reset(); fail_child = 1;
    assert(forkfix___fork() == -1 && errno == EPIPE);
    assert(patch_calls == 0 && waitpid(last_child, NULL, WNOHANG) == -1 && errno == ECHILD);
    assert(fd_count() == baseline);
    reset(); patch_result = -1;
    pid_t pid = forkfix___fork();
    if (pid == 0) ffsys_exit(99);
    assert(pid == -1 && errno == EIO && last_child > 0);
    assert(waitpid(last_child, NULL, WNOHANG) == -1 && errno == ECHILD);
    assert(fd_count() == baseline);
    reset();
    pid = forkfix___fork();
    if (pid == 0) ffsys_exit(0);
    int status;
    assert(pid > 0 && waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    assert(fd_count() == baseline);
    puts("PASS raw ARM64 errno, EINTR, EOF, EPIPE, patch failure, real fork, signal ordering and fd cleanup");
    return 0;
}
"""


def main():
    """直接编译项目汇编，并检查去掉中断重试会被测试拒绝。"""
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise SystemExit("This regression requires Darwin ARM64 to test the actual syscall ABI")
    source = (ROOT / "BaseBin/forkfix/src/main.c").read_text()
    actual = source[source.index("struct fork_pipes {"):source.index("void apply_fork_hook(void)")]
    assembly = (ROOT / "BaseBin/forkfix/src/syscall.S").read_text()
    assembly = ".text\n.align 4\n" + assembly[assembly.index(".global _ffsys_read"):]
    with tempfile.TemporaryDirectory(prefix="forkfix-handshake-", dir=ROOT / "worker") as temporary:
        directory = Path(temporary)
        asm = directory / "syscall.s"
        asm.write_text(assembly)
        for name, implementation in (
            ("current", actual),
            ("no-retry", actual.replace("while (transferred == -EINTR);", "while (false);")),
            ("accept-eof", actual.replace("if (transferred == 1) return 0;", "if (transferred >= 0) return 0;")),
        ):
            harness = directory / (name + ".c")
            binary = directory / name
            harness.write_text(STUBS + implementation + CASES)
            subprocess.run([os.environ.get("CC", "clang"), "-std=gnu11", "-O2", "-Werror",
                            str(harness), str(asm), "-o", str(binary)], check=True)
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=15)
            if name == "current":
                if result.returncode:
                    raise SystemExit(result.stderr or f"Current source failed: {result.returncode}")
                print(result.stdout.strip())
            elif result.returncode == 0:
                raise SystemExit("Mutation unexpectedly accepted: " + name)
            else:
                print("PASS regression mutation rejected: " + name)


if __name__ == "__main__":
    main()
