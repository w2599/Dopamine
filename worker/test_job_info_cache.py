#!/usr/bin/env python3
"""抽取真实任务缓存，在 ARC 下验证 uniqueid、淘汰与并发持有。"""

from pathlib import Path
import os
import re
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
from test_spawn_persona_guard import ROOT, extract_function

STUBS = r"""
#import <Foundation/Foundation.h>
#include <assert.h>
#include <limits.h>
#include <stdatomic.h>
static _Atomic uint64_t special_uniqueid = 700000;
static atomic_int registered, registrations, lookups[10000];
/* PID 7 可模拟复用；PID 9 可模拟黑名单注册与查询的竞争。 */
static uint64_t get_job_cache(pid_t pid) {
    if (pid == 0 || (pid == 9 && !atomic_load(&registered))) return 0;
    return pid == 7 ? atomic_load(&special_uniqueid) : (uint64_t)pid + 100000;
}
/* 仅在没有 uniqueid 的黑名单路径补登记。 */
static void register_job(pid_t pid) { atomic_fetch_add(&registrations, 1); atomic_store(&registered, 1); }
/* 用查询计数和 uniqueid 构造可验证的路径，不读取真实进程。 */
static void proc_get_path(pid_t pid, char *path) {
    atomic_fetch_add(&lookups[pid], 1);
    snprintf(path, PATH_MAX, "/test/%d/%llu", pid, get_job_cache(pid));
}
/* identifier 足够长，确保 UTF8String 使用对象管理的存储。 */
static void proc_get_identifier(pid_t pid, char *identifier) {
    snprintf(identifier, 255, "org.test.long.application.identifier.%d.%llu", pid, get_job_cache(pid));
}
"""

CASES = r"""
/* 缓存命中保留同一 uniqueid 的字典，超过上限后释放旧条目。 */
int main(void) {
    @autoreleasepool {
        assert(cachedJobInfo(0, false) == nil);
        assert(cachedJobInfo(9, false) == nil && atomic_load(&registrations) == 0);
        assert(cachedJobInfo(9, true) != nil && atomic_load(&registrations) == 1);
        NSDictionary *first = cachedJobInfo(7, false);
        assert(cachedJobInfo(7, false) == first && atomic_load(&lookups[7]) == 1);
        atomic_store(&special_uniqueid, 700001);
        NSDictionary *reused = cachedJobInfo(7, false);
        assert(reused != first && ![reused[@"path"] isEqual:first[@"path"]]);
        __weak NSDictionary *evicted;
        @autoreleasepool { evicted = cachedJobInfo(100, false); }
        for (int pid = 200; pid < 800; pid++) {
            @autoreleasepool {
                cachedJobInfo(pid, false);
                assert(cachedJobInfo(7, false) == reused);
            }
        }
        assert(evicted == nil);
        assert(atomic_load(&lookups[100]) == 1);
        cachedJobInfo(100, false);
        assert(atomic_load(&lookups[100]) == 2);
        __attribute__((objc_precise_lifetime)) NSDictionary *held = cachedJobInfo(800, false);
        const char *identifier = [held[@"identifier"] UTF8String];
        char expected[255];
        strlcpy(expected, identifier, sizeof(expected));
        dispatch_apply(1000, dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^(size_t index) {
            @autoreleasepool {
                pid_t pid = (pid_t)index + 1000;
                NSDictionary *job = cachedJobInfo(pid, false);
                assert(([job[@"path"] hasPrefix:[NSString stringWithFormat:@"/test/%d/", pid]]));
            }
        });
        assert(strcmp(identifier, expected) == 0);
        assert(atomic_load(&lookups[800]) == 1);
        assert(cachedJobInfo(800, false) != held && atomic_load(&lookups[800]) == 2);
        puts("PASS job cache: uniqueid reuse, registration, LRU bound, eviction and ARC concurrent lifetime");
    }
    return 0;
}
"""


def main():
    """以 ARC 和地址检查器运行真实缓存，确认取消上限会失败。"""
    source = (ROOT / "BaseBin/libroothider/src/xpc_hook.m").read_text()
    if re.search(r"cachedJobInfo\([^\n]+\)\s*\[", source):
        raise SystemExit("A caller still borrows UTF8String from an unowned cachedJobInfo temporary")
    actual = extract_function(source, "NSDictionary* cachedJobInfo(")
    with tempfile.TemporaryDirectory(prefix="job-cache-", dir=ROOT / "worker") as temporary:
        directory = Path(temporary)
        for name, implementation in (
            ("current", actual),
            ("unbounded", actual.replace("if (cachedData.count >= cacheLimit)", "if (false)")),
        ):
            harness = directory / (name + ".m")
            binary = directory / name
            harness.write_text(STUBS + implementation + CASES)
            subprocess.run([os.environ.get("CC", "clang"), "-fobjc-arc", "-fblocks", "-O2",
                            "-fsanitize=address", "-framework", "Foundation", str(harness),
                            "-o", str(binary)], check=True)
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=20)
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
