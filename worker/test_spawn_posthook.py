#!/usr/bin/env python3
"""抽取真实 posthook，验证底层错误、属性恢复和子进程处理。"""
from pathlib import Path
import os
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
from test_spawn_persona_guard import extract_function

ROOT = Path(__file__).resolve().parents[1]
STUBS = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <spawn.h>
#include <signal.h>
#include <mach/machine.h>
#include <xpc/xpc.h>
#include "envbuf.h"
#define NBINPREFS 4
#define POSIX_SPAWN_PROC_TYPE_DRIVER 0x700
typedef int kSpawnConfig;
enum { kSpawnConfigTrust = 1 };
struct _posix_spawn_args_desc { posix_spawnattr_t attrp; };
static int syscall_result, syscall_errno, syscall_calls, start_error, patch_error;
static int start_calls, cancel_calls, patch_calls, signal_calls, process_type;
static pid_t child_pid;
static bool expected_resume;
// 桩函数仅记录行为，不创建进程或向主机发送信号。
static bool jbclient_dyld_patch_enabled(void) { return true; }
static kSpawnConfig roothide_spawn_config_for_executable(const char *p, char *const a[]) { return 0; }
static int posix_spawnattr_getprocesstype_np(posix_spawnattr_t *a, int *t) { *t = process_type; return 0; }
static void jbclient_trust_executable_recurse(const char *p, xpc_object_t a) { assert(false); }
static void trust_insert_libraries(char **e) { assert(false); }
static int jbdSpawnExecStart(const char *p, bool resume) { start_calls++; assert(resume == expected_resume); return start_error; }
static void jbdSpawnExecCancel(const char *p) { cancel_calls++; errno = EINTR; }
static int jbdSpawnPatchChild(pid_t pid, bool resume) {
    patch_calls++; assert(pid == child_pid && resume == expected_resume); errno = EIO; return patch_error;
}
static int test_kill(pid_t pid, int sig) { signal_calls++; assert(pid == child_pid); errno = ESRCH; return 0; }
#define kill test_kill
static int __posix_spawn_inline(pid_t *pid, const char *p, struct _posix_spawn_args_desc *d, char *const a[], char *const e[]) {
    syscall_calls++;
    // 失败时故意不写 PID，避免测试掩盖读取未初始化输出的问题。
    if (syscall_result == 0) *pid = child_pid;
    errno = syscall_errno;
    return syscall_result;
}
void real_envbuf_free(char *envp[]);
// 故意覆盖 errno，验证生产 posthook 独立保留底层错误。
void envbuf_free(char *envp[]) { real_envbuf_free(envp); errno = 0; }
'''

CASES = r'''
// 使用真实 spawn 属性 API，覆盖失败、SETEXEC、主动挂起和修复失败。
int main(void) {
    for (int mode = 0; mode < 9; mode++) {
        posix_spawnattr_t attr;
        assert(posix_spawnattr_init(&attr) == 0);
        short original_flags = mode == 2 || mode == 7 ? POSIX_SPAWN_SETEXEC :
            mode == 4 ? POSIX_SPAWN_START_SUSPENDED : 0;
        assert(posix_spawnattr_setflags(&attr, original_flags) == 0);
        struct _posix_spawn_args_desc desc = { attr };
        syscall_result = mode < 3 ? -1 : mode == 8 ? EACCES : 0;
        syscall_errno = mode == 1 ? EACCES : ENOENT;
        child_pid = mode == 5 ? 0 : 4321;
        start_error = mode == 7 ? EIO : 0;
        patch_error = mode == 6 ? EIO : 0;
        process_type = 0;
        expected_resume = !(original_flags & POSIX_SPAWN_START_SUSPENDED);
        syscall_calls = start_calls = cancel_calls = patch_calls = signal_calls = 0;
        char *env[] = { "DYLD_INSERT_LIBRARIES=/test/hook.dylib", NULL };
        pid_t pid;
        int result = roothide_systemhook___posix_spawn_posthook(mode == 3 ? NULL : &pid, "/test/tool", &desc, NULL, env);
        int actual_errno = errno;
        short flags;
        assert(posix_spawnattr_getflags(&attr, &flags) == 0);
        assert(flags == original_flags);
        assert(result == (mode == 7 ? 201 : mode == 6 ? 202 : syscall_result));
        assert(syscall_calls == (mode == 7 ? 0 : 1));
        assert(start_calls == (mode == 2 || mode == 7));
        assert(cancel_calls == (mode == 2));
        assert(patch_calls == (mode == 3 || mode == 4 || mode == 6));
        assert(signal_calls == (mode == 6 ? 2 : 0));
        if (mode != 6 && mode != 7) assert(actual_errno == syscall_errno);
        assert(posix_spawnattr_destroy(&attr) == 0);
    }
    puts("PASS 9 actual posthook error and cleanup cases");
    return 0;
}
'''


def main():
    """编译生产函数，并确认删除 errno 恢复会被测试拒绝。"""
    source = (ROOT / "BaseBin/systemhook/src/roothider_main.c").read_text()
    actual = extract_function(source, "int roothide_systemhook___posix_spawn_posthook(")
    compiler = os.environ.get("CC", "clang")
    common = ROOT / "BaseBin/systemhook/src/common"
    with tempfile.TemporaryDirectory(prefix="spawn-posthook-", dir=ROOT / "worker") as temporary:
        directory = Path(temporary)
        envbuf = directory / "envbuf.o"
        subprocess.run([compiler, "-Denvbuf_free=real_envbuf_free", "-c", str(common / "envbuf.c"), "-o", str(envbuf)], check=True)
        for name, implementation in (("current", actual), ("missing-errno", actual.replace("errno = savedErrno;", ""))):
            harness, binary = directory / (name + ".c"), directory / name
            harness.write_text(STUBS + implementation + CASES)
            subprocess.run([compiler, "-std=gnu11", "-fblocks", "-O1", "-g", "-fsanitize=address,undefined",
                            "-Werror=implicit-function-declaration", "-Wno-incompatible-pointer-types-discards-qualifiers",
                            "-I", str(common), str(harness), str(envbuf), "-o", str(binary)], check=True)
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=15)
            if name == "current":
                if result.returncode:
                    raise SystemExit(result.stderr)
                print(result.stdout, end="")
            elif result.returncode == 0:
                raise SystemExit("Mutation incorrectly accepted: missing errno preservation")
            else:
                print("PASS missing errno preservation rejected")


if __name__ == "__main__":
    main()
