#!/usr/bin/env python3
"""抽取真实启动函数，验证解析状态、内存额度和属性初始化失败。"""

from pathlib import Path
import os
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
from test_spawn_persona_guard import ROOT, STUBS, extract_function


TOKEN_CASES = r"""
/* 回调重入和调用方 strtok 不能互相覆盖解析状态。 */
int main(void) {
    char caller[] = "first:second";
    if (strcmp(strtok(caller, ":"), "first")) return 1;
    __block int outer = 0, inner = 0;
    string_enumerate_components("outerA::outerB", ":", ^(const char *item, bool *stop) {
        outer++;
        if (outer == 1) string_enumerate_components("innerA,innerB", ",", ^(const char *part, bool *end) {
            inner++;
        });
    });
    char *second = strtok(NULL, ":");
    if (outer != 2 || inner != 2 || !second || strcmp(second, "second")) return 2;
    __block int count = 0;
    string_enumerate_components("a:b", ":", ^(const char *part, bool *stop) { count++; *stop = true; });
    string_enumerate_components("", ":", ^(const char *part, bool *stop) { count++; });
    if (count != 1) return 3;
    puts("PASS tokenizer caller state, nested callbacks, early stop and empty input");
    return 0;
}
"""

JET_CASES = r"""
/* 每次传给底层的额度只增加一次，调用者可重试失败或复用成功的属性。 */
int main(void) {
    const int limits[][2] = {{100, 200}, {-1, 200}, {100, -1}, {-1, -1}, {INT_MAX-2, INT_MAX}};
    const int results[] = {-1, EACCES, 0};
    const double multipliers[] = {3, 1, 0, NAN, INFINITY};
    size_t checked = 0;
    for (int mode = 0; mode < 4; mode++)
    for (size_t l = 0; l < sizeof(limits)/sizeof(*limits); l++)
    for (size_t r = 0; r < sizeof(results)/sizeof(*results); r++)
    for (size_t m = 0; m < sizeof(multipliers)/sizeof(*multipliers); m++) {
        struct test_attr attr = {limits[l][0], limits[l][1], NULL, 0};
        struct _posix_spawn_args_desc desc = {&attr};
        char *inserted[] = {"DYLD_INSERT_LIBRARIES=/test/systemhook.dylib", NULL};
        char *empty[] = {NULL};
        char **env = (mode == 0 || mode == 3) ? inserted : empty;
        config = kSpawnConfigTrust | (mode < 2 ? kSpawnConfigInject : 0);
        for (int attempt = 0; attempt < 2; attempt++) {
            int expected = attempt ? 0 : results[r];
            int addend = mode < 2 && multipliers[m] != 1 ? 40 : 0;
            int active = limits[l][0] == -1 ? -1 : (int)min((int64_t)INT_MAX, (int64_t)limits[l][0] + addend);
            int inactive = limits[l][1] == -1 ? -1 : (int)min((int64_t)INT_MAX, (int64_t)limits[l][1] + addend);
            __block int calls = 0;
            int ret = spawn_exec_hook_common(false, "/test/tool", NULL, env, &desc, trust_binary,
                multipliers[m], ^int(pid_t *pid, char *const patched[]) {
                    calls++;
                    if (desc.attrp->active != active || desc.attrp->inactive != inactive) exit(10);
                    if (expected == 0) *pid = 123;
                    errno = ENOENT;
                    return expected;
                });
            if (ret != expected || errno != ENOENT || calls != 1
                || attr.active != limits[l][0] || attr.inactive != limits[l][1]) return 11;
            checked++;
        }
    }
    printf("PASS %zu Jetsam success/failure/reuse, finite/unlimited/saturated and environment cases\n", checked);
    return 0;
}
"""

PRE_STUBS = r"""
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
typedef void *posix_spawnattr_t;
struct _posix_spawn_args_desc { posix_spawnattr_t attrp; void *file_actions; };
static int init_result, spawn_result, init_calls, spawn_calls, destroy_calls, shared_calls, inline_calls;
static void *expected_actions;
static int (*expected_trust)(const char *);
static int roothide_systemhook___posix_spawn_prehook(pid_t *, const char *, struct _posix_spawn_args_desc *, char *const [], char *const [], void *, int (*)(const char *), int (*)(uint64_t, bool), double);
/* 模拟属性分配的失败和成功。 */
static int posix_spawnattr_init(posix_spawnattr_t *attr) {
    init_calls++;
    if (!init_result) *attr = (void *)1;
    return init_result;
}
/* 清理故意覆盖 errno，验证真实函数保留底层错误。 */
static int posix_spawnattr_destroy(posix_spawnattr_t *attr) { destroy_calls++; errno = EBUSY; return 0; }
/* 公开 API 重新进入实际 prehook；旧代码会反复走初始化失败分支。 */
static int posix_spawn(pid_t *pid, const char *path, void **actions, const posix_spawnattr_t *attr,
    char *const argv[], char *const env[]) {
    if (++spawn_calls > 4) return ELOOP;
    if ((actions ? *actions : NULL) != expected_actions) exit(20);
    struct _posix_spawn_args_desc desc = {*attr, actions ? *actions : NULL};
    return roothide_systemhook___posix_spawn_prehook(pid, path, &desc, argv, env, NULL, expected_trust, NULL, 3);
}
/* 正常路径只经过一次共享 hook。 */
static int posix_spawn_hook_shared(pid_t *pid, const char *path, struct _posix_spawn_args_desc *desc,
    char *const argv[], char *const env[], void *orig, int (*trust)(const char *), int (*debug)(uint64_t, bool), double multiplier) {
    shared_calls++; errno = ENOENT;
    if (!spawn_result && pid) *pid = 456;
    return spawn_result;
}
/* 空路径交给原系统调用处理。 */
static int __posix_spawn_inline(pid_t *pid, const char *path, struct _posix_spawn_args_desc *desc,
    char *const argv[], char *const env[]) { inline_calls++; return EFAULT; }
/* 测试启用原信任逻辑。 */
static bool jbclient_dyld_patch_enabled(void) { return true; }
/* 保留未启用补丁时所需的函数符号。 */
static int __no_need_to_trust_now__(const char *path) { return 0; }
"""

PRE_CASES = r"""
/* 缺失属性的成功、失败和资源清理必须遵循公开 spawn 返回约定。 */
int main(void) {
    const int outcomes[] = {-1, EACCES, 0};
    for (int missing_desc = 0; missing_desc < 2; missing_desc++) {
        struct _posix_spawn_args_desc desc = {NULL, (void *)2};
        expected_actions = missing_desc ? NULL : desc.file_actions;
        init_result = ENOMEM;
        init_calls = spawn_calls = destroy_calls = shared_calls = 0;
        int ret = roothide_systemhook___posix_spawn_prehook(NULL, "/test/tool", missing_desc ? NULL : &desc,
            NULL, NULL, NULL, NULL, NULL, 3);
        if (ret != ENOMEM || init_calls != 1 || spawn_calls || destroy_calls || shared_calls) return 21;
        for (size_t i = 0; i < sizeof(outcomes)/sizeof(*outcomes); i++) {
            init_result = 0; spawn_result = outcomes[i];
            init_calls = spawn_calls = destroy_calls = shared_calls = 0;
            pid_t pid = -1;
            ret = roothide_systemhook___posix_spawn_prehook(&pid, "/test/tool", missing_desc ? NULL : &desc,
                NULL, NULL, NULL, NULL, NULL, 3);
            if (ret != outcomes[i] || errno != ENOENT || init_calls != 1 || spawn_calls != 1
                || destroy_calls != 1 || shared_calls != 1 || (!ret && pid != 456)) return 22;
        }
    }
    if (roothide_systemhook___posix_spawn_prehook(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 3)
        != EFAULT || inline_calls != 1) return 23;
    puts("PASS prehook initialization failure, recursive public API, cleanup, errno and NULL path");
    return 0;
}
"""


def main():
    """编译真实函数，并用故障变体验证断言能检出原问题。"""
    common = (ROOT / "BaseBin/systemhook/src/common/common.c").read_text()
    enumeration = extract_function(common, "void string_enumerate_components(")
    spawn = extract_function(common, "static int spawn_exec_hook_common(")
    prehook = extract_function((ROOT / "BaseBin/systemhook/src/roothider_main.c").read_text(),
                               "int roothide_systemhook___posix_spawn_prehook(")
    with tempfile.TemporaryDirectory(prefix="spawn-runtime-", dir=ROOT / "worker") as temporary:
        directory = Path(temporary)
        environment = directory / "envbuf.c"
        environment.write_text((ROOT / "BaseBin/systemhook/src/common/envbuf.c").read_text().replace(
            "void envbuf_free(", "void real_envbuf_free("))
        cases = [
            ("tokenizer", STUBS + enumeration + TOKEN_CASES, True),
            ("tokenizer-old", STUBS + enumeration.replace("strtok_r(stringCopy, separator, &state)",
                "strtok(stringCopy, separator)").replace("strtok_r(NULL, separator, &state)",
                "strtok(NULL, separator)") + TOKEN_CASES, False),
            ("jetsam", STUBS + enumeration + spawn + JET_CASES, True),
            ("jetsam-no-restore", STUBS + enumeration + spawn.replace("if (modifiedMemlimits) {", "if (false) {") + JET_CASES, False),
            ("prehook", PRE_STUBS + prehook + PRE_CASES, True),
            ("prehook-no-check", PRE_STUBS + prehook.replace("if (initResult != 0) return initResult;", "") + PRE_CASES, False),
            ("prehook-no-errno", PRE_STUBS + prehook.replace("errno = spawnError;", "") + PRE_CASES, False),
        ]
        for name, source, should_pass in cases:
            harness = directory / (name + ".c")
            binary = directory / name
            harness.write_text(source)
            subprocess.run([os.environ.get("CC", "clang"), "-std=gnu11", "-fblocks", "-O2",
                            "-Werror=implicit-function-declaration", str(harness),
                            *([str(environment)] if not name.startswith("prehook") else []),
                            "-o", str(binary)], check=True)
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
            if (result.returncode == 0) != should_pass:
                raise SystemExit(f"FAIL {name}: status={result.returncode} {result.stderr}")
            print(result.stdout.strip() if should_pass else f"PASS regression mutation rejected: {name}")


if __name__ == "__main__":
    main()
