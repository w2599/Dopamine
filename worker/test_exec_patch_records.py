#!/usr/bin/env python3
"""抽取真实 exec 监听管理函数，检查故障清理、串行化与过期事件。"""

from pathlib import Path
import os
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
from test_spawn_persona_guard import ROOT, extract_function

STUBS = r"""
#import <Foundation/Foundation.h>
#include <sys/event.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>
#define JBLogError(...) ((void)0)
#define JBLogDebug(...) ((void)0)
static int kq = 42;
static dispatch_queue_t gExecPatchDataQueue;
static NSMutableDictionary *gExecPatchArray;
static uintptr_t gExecPatchGeneration;
static NSMutableDictionary *kernelWatches;
static int add_error, delete_error, interrupts, patch_result, patch_calls, signal_calls;
static void *queueKey = &queueKey;
/* 每次内核监听变更必须与字典操作处于同一串行队列。 */
static int test_kevent(int fd, const struct kevent *changes, int count, struct kevent *events,
    int n, const struct timespec *timeout) {
    assert(dispatch_get_specific(queueKey) == queueKey);
    assert(count == 1);
    if (interrupts) { interrupts--; errno = EINTR; return -1; }
    NSNumber *pid = @(changes->ident);
    if (changes->flags & EV_ADD) {
        if (add_error) { errno = add_error; return -1; }
        kernelWatches[pid] = @((uintptr_t)changes->udata);
    } else {
        if (delete_error) { errno = delete_error; return -1; }
        if (!kernelWatches[pid]) { errno = ENOENT; return -1; }
        [kernelWatches removeObjectForKey:pid];
    }
    return 0;
}
/* 数据队列在测试入口真实初始化，避免启动无限等待的事件线程。 */
static void initExecPatch(void) {}
/* 修复过程也在串行队列内，防止消费旧事件时插入新记录。 */
static int roothide_patch_proc(pid_t pid) {
    assert(dispatch_get_specific(queueKey) == queueKey);
    patch_calls++; return patch_result;
}
/* 不向真实进程发送测试信号。 */
static int test_kill(pid_t pid, int signal) { signal_calls++; return 0; }
#define kevent(...) test_kevent(__VA_ARGS__)
#define kill test_kill
"""

CASES = r"""
#undef kevent
/* 模拟内核已经出队的一次性事件，保留注册时的 udata。 */
static struct kevent take_event(pid_t pid, unsigned flags) {
    struct kevent event;
    EV_SET(&event, pid, EVFILT_PROC, EV_ONESHOT, flags, 0,
        (void *)(uintptr_t)[kernelWatches[@(pid)] unsignedLongLongValue]);
    [kernelWatches removeObjectForKey:@(pid)];
    return event;
}
/* 清理故障、替换监听和旧事件竞争都不能留下或误删记录。 */
int main(void) {
    @autoreleasepool {
        gExecPatchDataQueue = dispatch_queue_create("test.execpatch", DISPATCH_QUEUE_SERIAL);
        dispatch_queue_set_specific(gExecPatchDataQueue, queueKey, queueKey, NULL);
        gExecPatchArray = [NSMutableDictionary new];
        kernelWatches = [NSMutableDictionary new];
        assert(spawnExecPatchAdd(100, true) == 0);
        struct kevent event = take_event(100, NOTE_EXIT);
        handle_exec_patch_event(&event);
        assert(gExecPatchArray.count == 0 && patch_calls == 0 && signal_calls == 0);
        add_error = ENOMEM;
        assert(spawnExecPatchAdd(100, true) == -1 && errno == ENOMEM);
        assert(gExecPatchArray.count == 0);
        add_error = 0;
        for (int failure = 0; failure < 3; failure++) {
            assert(spawnExecPatchAdd(100, false) == 0);
            delete_error = failure == 1 ? ENOENT : failure == 2 ? EIO : 0;
            int result = spawnExecPatchDel(100);
            assert(result == (failure ? -1 : 0));
            assert(!failure || errno == delete_error);
            assert(gExecPatchArray.count == 0);
            delete_error = 0;
        }
        assert(spawnExecPatchAdd(100, true) == 0);
        struct kevent old = take_event(100, NOTE_EXEC);
        assert(spawnExecPatchAdd(100, false) == 0);
        handle_exec_patch_event(&old);
        assert(gExecPatchArray.count == 1 && patch_calls == 0);
        event = take_event(100, NOTE_EXEC);
        handle_exec_patch_event(&event);
        assert(gExecPatchArray.count == 0 && patch_calls == 1 && signal_calls == 0);
        assert(spawnExecPatchAdd(100, true) == 0);
        event = take_event(100, NOTE_EXEC);
        handle_exec_patch_event(&event);
        assert(patch_calls == 2 && signal_calls == 1 && gExecPatchArray.count == 0);
        assert(spawnExecPatchAdd(100, true) == 0);
        event = take_event(100, NOTE_EXEC | NOTE_EXIT);
        handle_exec_patch_event(&event);
        assert(patch_calls == 2 && gExecPatchArray.count == 0);
        assert(spawnExecPatchAdd(100, true) == 0);
        patch_result = -1;
        event = take_event(100, NOTE_EXEC);
        handle_exec_patch_event(&event);
        assert(patch_calls == 3 && signal_calls == 3 && gExecPatchArray.count == 0);
        interrupts = 2;
        assert(spawnExecPatchAdd(100, true) == 0 && interrupts == 0);
        delete_error = EIO;
        assert(spawnExecPatchAdd(100, false) == -1 && errno == EIO && gExecPatchArray.count == 0);
        delete_error = 0;
        assert(spawnExecPatchAdd(100, false) == 0);
        assert(spawnExecPatchDel(100) == 0);
        dispatch_apply(200, dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^(size_t index) {
            pid_t pid = (pid_t)index + 1000;
            assert(spawnExecPatchAdd(pid, false) == 0);
            assert(spawnExecPatchDel(pid) == 0);
        });
        assert(gExecPatchArray.count == 0 && kernelWatches.count == 0);
        puts("PASS exec records: exit, add/delete errors, errno, generation, patch/resume and concurrent updates");
    }
    return 0;
}
"""


def main():
    """编译真实管理函数，并确认移除代次检查或退出清理会失败。"""
    source = (ROOT / "BaseBin/libroothider/src/exec_patch.m").read_text()
    implementation = "".join(extract_function(source, name) for name in (
        "static int change_exec_patch_event(", "static void handle_exec_patch_event(",
        "int spawnExecPatchAdd(", "int spawnExecPatchDel("))
    with tempfile.TemporaryDirectory(prefix="exec-patch-", dir=ROOT / "worker") as temporary:
        directory = Path(temporary)
        for name, actual in (
            ("current", implementation),
            ("no-generation", implementation.replace(
                ' || [record[@"generation"] unsignedLongLongValue] != (uintptr_t)event->udata', "")),
            ("keep-exit", implementation.replace(
                '[gExecPatchArray removeObjectForKey:@(pid)];\n        if(event->fflags',
                'if (!(event->fflags & NOTE_EXIT)) [gExecPatchArray removeObjectForKey:@(pid)];\n        if(event->fflags')),
        ):
            harness = directory / (name + ".m")
            binary = directory / name
            harness.write_text(STUBS + actual + CASES)
            subprocess.run([os.environ.get("CC", "clang"), "-fobjc-arc", "-fblocks", "-O2",
                            "-framework", "Foundation", str(harness), "-o", str(binary)], check=True)
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
