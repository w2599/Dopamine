#!/usr/bin/env python3
"""抽取实际启动函数，用主机桩函数验证 persona 的失败与成功路径。"""

from pathlib import Path
import os
import re
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "BaseBin/systemhook/src/common/common.c"


def extract_function(source, declaration):
    """保留实际函数源码，不在测试中重写启动逻辑。"""
    start = source.index(declaration)
    body = source.index("{", start)
    tokens = re.compile(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{}]', re.S)
    depth = 0
    for token in tokens.finditer(source, body):
        value = token.group()
        if value == "{":
            depth += 1
        elif value == "}":
            depth -= 1
            if depth == 0:
                return source[start:token.end()] + "\n"
    raise ValueError("Unterminated C function: " + declaration)


STUBS = r"""
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <limits.h>
#include <sys/types.h>
#include <signal.h>
#include <errno.h>

#define min(a,b) ((a) < (b) ? (a) : (b))
#define F_OK 0
#define POSIX_SPAWN_SETEXEC 0x40
#define POSIX_SPAWN_START_SUSPENDED 0x80
#define POSIX_SPAWN_PROC_TYPE_DRIVER 0x700
#define POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE 1
#define POSIX_SPAWN_PERSONA_UID 2
#define POSIX_SPAWN_PERSONA_GID 4
struct _posix_spawn_persona_info { int pspi_id, pspi_flags, pspi_uid, pspi_gid; };
struct test_attr {
    int active, inactive;
    struct _posix_spawn_persona_info *persona;
    short flags;
};
typedef struct test_attr *posix_spawnattr_t;
struct _posix_spawn_args_desc { posix_spawnattr_t attrp; };
#define POSIX_SPAWNATTR_OFF_MEMLIMIT_ACTIVE offsetof(struct test_attr, active)
#define POSIX_SPAWNATTR_OFF_MEMLIMIT_INACTIVE offsetof(struct test_attr, inactive)
#define POSIX_SPAWNATTR_OFF_PERSONA offsetof(struct test_attr, persona)
typedef int kSpawnConfig;
enum { kSpawnConfigTrust = 1, kSpawnConfigInject = 2 };
static const char *HOOK_DYLIB_PATH = "/test/systemhook.dylib";
static int config, persona_calls, signal_calls, cleanup_calls, debug_calls;
static pid_t persona_pid, signal_pid;
static int fixed_uid, fixed_gid, sent_signal;
static uid_t caller_uid = 501;

/* 模拟系统调用，绝不向主机真实进程发信号。 */
static int test_kill(pid_t pid, int signal) {
    signal_calls++; signal_pid = pid; sent_signal = signal; errno = ESRCH; return 0;
}
/* 模拟非 root 调用者和可访问的注入文件。 */
static uid_t test_getuid(void) { return caller_uid; }
/* 避免依赖主机上的注入文件。 */
static int test_access(const char *path, int mode) { return 0; }
#define kill test_kill
#define getuid test_getuid
#define access test_access
/* 子进程修复也会改写 errno，返回时必须保留原启动结果。 */
static int jbclient_persona_fix(pid_t pid, int uid, int gid) {
    persona_calls++; persona_pid = pid; fixed_uid = uid; fixed_gid = gid; errno = EIO; return 0;
}
/* 固定使用普通进程类型。 */
static int posix_spawnattr_getprocesstype_np(posix_spawnattr_t *attr, int *type) {
    *type = 0; return 0;
}
/* 模拟属性读取可能改写 errno。 */
static int posix_spawnattr_getflags(posix_spawnattr_t *attr, short *flags) {
    *flags = (*attr)->flags; errno = ERANGE; return 0;
}
/* 模拟属性恢复可能改写 errno。 */
static int posix_spawnattr_setflags(posix_spawnattr_t *attr, short flags) {
    (*attr)->flags = flags; errno = EINVAL; return 0;
}
/* 返回当前用例的注入策略。 */
static kSpawnConfig spawn_config_for_executable(const char *path, char *const argv[]) {
    return config;
}
/* 安全模式用例不允许注入。 */
static bool allowInjectWithSafeMode(const char *path) { return false; }
/* 测试保持原内存额度，不依赖外部配置。 */
static int zqbb_getJetsamAddend(const char *path) { return 10; }
/* 信任操作不访问设备。 */
static int trust_binary(const char *path) { return 0; }
/* 记录外层挂起进程处理，同时覆盖 errno。 */
static int set_process_debugged(uint64_t pid, bool fully_debugged) {
    debug_calls++; errno = EBUSY; return 0;
}
char **envbuf_mutcopy(const char *envp[]);
void real_envbuf_free(char *envp[]);
/* 使用真实清理逻辑，再模拟 Darwin free 可能改写 errno。 */
static void envbuf_free(char *envp[]) {
    real_envbuf_free(envp); cleanup_calls++; errno = 0;
}
const char *envbuf_getenv(const char *envp[], const char *name);
void envbuf_setenv(char **envpp[], const char *name, const char *value);
void envbuf_unsetenv(char **envpp[], const char *name);
"""


CASES = r"""
struct scenario {
    const char *name;
    int result;
    pid_t child;
    int uid, gid;
    bool suspended, is_exec;
    int fixes, resumes;
};

static int expected_uid, expected_gid, expected_flags, original_calls;
static int original_result;

/* 从完整共享 hook 校验内核实际收到的临时属性。 */
static int original_spawn(pid_t *pid, const char *path, struct _posix_spawn_args_desc *desc,
    char *const argv[], char *const envp[]) {
    original_calls++;
    struct test_attr *attr = desc->attrp;
    if (attr->persona->pspi_uid != expected_uid || attr->persona->pspi_gid != expected_gid
        || attr->flags != expected_flags) {
        fprintf(stderr, "FAIL attributes at spawn: uid=%d gid=%d flags=%x expected=%d/%d/%x\n",
            attr->persona->pspi_uid, attr->persona->pspi_gid, attr->flags,
            expected_uid, expected_gid, expected_flags);
        exit(1);
    }
    if (original_result == 0) *pid = 4321;
    errno = ENOENT;
    return original_result;
}

/* 失败重试和成功复用都必须重新提权，且保持调用者属性及原 errno。 */
static size_t run_reuse_cases(void) {
    const struct {
        const char *name;
        int uid, gid, persona_flags;
        short flags;
    } cases[] = {
        {"both root", 0, 0, POSIX_SPAWN_PERSONA_UID | POSIX_SPAWN_PERSONA_GID, 0},
        {"root uid mixed gid", 0, 20, POSIX_SPAWN_PERSONA_UID | POSIX_SPAWN_PERSONA_GID, 0},
        {"root gid mixed uid", 502, 0, POSIX_SPAWN_PERSONA_UID | POSIX_SPAWN_PERSONA_GID, 0},
        {"uid only", 0, 0, POSIX_SPAWN_PERSONA_UID, 0},
        {"gid only", 0, 0, POSIX_SPAWN_PERSONA_GID, 0},
        {"nonroot", 502, 20, POSIX_SPAWN_PERSONA_UID | POSIX_SPAWN_PERSONA_GID, 0},
        {"already suspended", 0, 0, POSIX_SPAWN_PERSONA_UID | POSIX_SPAWN_PERSONA_GID,
            POSIX_SPAWN_START_SUSPENDED},
    };
    const int first_results[] = {-1, EACCES, 0};
    size_t checked = 0;
    for (int env_mode = 0; env_mode < 4; env_mode++) {
        for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); i++) {
            for (size_t outcome = 0; outcome < sizeof(first_results) / sizeof(*first_results); outcome++) {
                struct _posix_spawn_persona_info persona = {
                    99, POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE | cases[i].persona_flags,
                    cases[i].uid, cases[i].gid
                };
                short original_flags = cases[i].flags | 0x02;
                struct test_attr attr = {-1, -1, &persona, original_flags};
                struct _posix_spawn_args_desc desc = {&attr};
                bool fix_uid = (cases[i].persona_flags & POSIX_SPAWN_PERSONA_UID) && cases[i].uid == 0;
                bool fix_gid = (cases[i].persona_flags & POSIX_SPAWN_PERSONA_GID) && cases[i].gid == 0;
                bool fix_persona = fix_uid || fix_gid;
                expected_uid = fix_uid ? 501 : cases[i].uid;
                expected_gid = fix_gid ? 501 : cases[i].gid;
                expected_flags = original_flags | (fix_persona ? POSIX_SPAWN_START_SUSPENDED : 0);
                char *inserted[] = {"DYLD_INSERT_LIBRARIES=/test/systemhook.dylib", NULL};
                char *empty[] = {NULL};
                char **env = (env_mode == 0 || env_mode == 3) ? inserted : empty;
                config = kSpawnConfigTrust | (env_mode < 2 ? kSpawnConfigInject : 0);
                for (int attempt = 0; attempt < 2; attempt++) {
                    original_result = attempt == 0 ? first_results[outcome] : 0;
                    persona_calls = signal_calls = cleanup_calls = debug_calls = original_calls = 0;
                    pid_t pid = -1;
                    int result = posix_spawn_hook_shared(&pid, "/test/tool", &desc, NULL, env,
                        original_spawn, trust_binary, set_process_debugged, 1.0);
                    int saved_errno = errno;
                    bool valid = result == original_result && saved_errno == ENOENT
                        && original_calls == 1 && attr.flags == original_flags
                        && persona.pspi_uid == cases[i].uid && persona.pspi_gid == cases[i].gid
                        && persona.pspi_flags == (POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE | cases[i].persona_flags)
                        && persona_calls == (original_result == 0 && fix_persona)
                        && signal_calls == (original_result == 0 && fix_persona && !cases[i].flags)
                        && debug_calls == (original_result == 0 && cases[i].flags != 0)
                        && cleanup_calls == (env_mode == 1 || env_mode == 3);
                    if (persona_calls) {
                        int uid = (cases[i].persona_flags & POSIX_SPAWN_PERSONA_UID) ? cases[i].uid : -1;
                        int gid = (cases[i].persona_flags & POSIX_SPAWN_PERSONA_GID) ? cases[i].gid : -1;
                        valid &= persona_pid == 4321 && fixed_uid == uid && fixed_gid == gid;
                    }
                    if (signal_calls) valid &= signal_pid == 4321 && sent_signal == SIGCONT;
                    if (!valid) {
                        fprintf(stderr, "FAIL reuse %s env=%d first=%d attempt=%d ret=%d errno=%d attr=%d/%d/%x fixes=%d signals=%d debug=%d\n",
                            cases[i].name, env_mode, first_results[outcome], attempt, result, saved_errno,
                            persona.pspi_uid, persona.pspi_gid, attr.flags, persona_calls, signal_calls, debug_calls);
                        exit(1);
                    }
                    checked++;
                }
            }
        }
    }
    return checked;
}

/* 验证失败不能碰任何 PID，成功只修复有效子进程，并尊重原挂起状态。 */
int main(void) {
    const struct scenario cases[] = {
        {"failure uid root", -1, -1, 0, 501, false, false, 0, 0},
        {"failure gid root", -1, -1, 501, 0, false, false, 0, 0},
        {"failure both root", -1, -1, 0, 0, false, false, 0, 0},
        {"failure positive error", EACCES, -1, 0, 0, false, false, 0, 0},
        {"failure stale positive pid", -1, 4321, 0, 0, false, false, 0, 0},
        {"success invalid zero pid", 0, 0, 0, 0, false, false, 0, 0},
        {"success invalid negative pid", 0, -1, 0, 0, false, false, 0, 0},
        {"success root uid", 0, 4321, 0, 501, false, false, 1, 1},
        {"success root gid", 0, 4321, 501, 0, false, false, 1, 1},
        {"success both root", 0, 4321, 0, 0, false, false, 1, 1},
        {"success nonroot", 0, 4321, 501, 501, false, false, 0, 0},
        {"success already suspended", 0, 4321, 0, 0, true, false, 1, 0},
        {"exec failure", -1, -1, 0, 0, false, true, 0, 0},
    };
    size_t checked = 0;
    for (int env_mode = 0; env_mode < 4; env_mode++) {
        for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); i++) {
            struct scenario c = cases[i];
            struct _posix_spawn_persona_info persona = {
                99, POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE | POSIX_SPAWN_PERSONA_UID | POSIX_SPAWN_PERSONA_GID,
                c.uid, c.gid
            };
            struct test_attr attr = { -1, -1, &persona, c.suspended ? POSIX_SPAWN_START_SUSPENDED : 0 };
            struct _posix_spawn_args_desc desc = { &attr };
            char *inserted[] = {"DYLD_INSERT_LIBRARIES=/test/systemhook.dylib", NULL};
            char *empty[] = {NULL};
            char **env = (env_mode == 0 || env_mode == 3) ? inserted : empty;
            config = kSpawnConfigTrust | (env_mode < 2 ? kSpawnConfigInject : 0);
            persona_calls = signal_calls = cleanup_calls = 0;
            __block int orig_calls = 0;
            int result = spawn_exec_hook_common(c.is_exec, "/test/tool", NULL, env,
                &desc, trust_binary, 1.0, ^int(pid_t *pid, char *const envp[]) {
                    orig_calls++;
                    *pid = c.child;
                    errno = EACCES;
                    return c.result;
                });
            int saved_errno = errno;
            bool valid = result == c.result && orig_calls == 1 && saved_errno == EACCES
                && persona_calls == c.fixes && signal_calls == c.resumes
                && persona.pspi_uid == c.uid && persona.pspi_gid == c.gid
                && attr.flags == (c.suspended ? POSIX_SPAWN_START_SUSPENDED : 0)
                && cleanup_calls == (env_mode == 1 || env_mode == 3);
            if (c.fixes) valid &= persona_pid == c.child && fixed_uid == c.uid && fixed_gid == c.gid;
            if (c.resumes) valid &= signal_pid == c.child && sent_signal == SIGCONT;
            if (!valid) {
                fprintf(stderr, "FAIL %s env=%d result=%d errno=%d persona=%d signal=%d pid=%d attr=%d/%d/%x\n",
                    c.name, env_mode, result, saved_errno, persona_calls, signal_calls, (int)signal_pid,
                    persona.pspi_uid, persona.pspi_gid, attr.flags);
                return 1;
            }
            checked++;
        }
    }
    printf("PASS %zu fault-injection cases against actual spawn_exec_hook_common\n", checked);
    printf("PASS %zu repeated spawns against actual posix_spawn_hook_shared\n", run_reuse_cases());
    return 0;
}
"""


def main():
    """编译真实调用链，并确认删去 PID、属性恢复或 errno 保护都会失败。"""
    source = SOURCE.read_text()
    actual = extract_function(source, "static int spawn_exec_hook_common(")
    shared = extract_function(source, "int posix_spawn_hook_shared(")
    enumerate_components = extract_function(source, "void string_enumerate_components(")
    fixed = "r == 0 && childPid > 0 && (personaFixUid == 0 || personaFixGid == 0)"
    if actual.count(fixed) != 1:
        raise SystemExit("Missing expected guarded persona condition in actual source")
    compiler = os.environ.get("CC", "clang")
    with tempfile.TemporaryDirectory(prefix="spawn-persona-", dir=ROOT / "worker") as temporary:
        directory = Path(temporary)
        environment = directory / "envbuf.c"
        environment.write_text((ROOT / "BaseBin/systemhook/src/common/envbuf.c").read_text().replace(
            "void envbuf_free(", "void real_envbuf_free("))
        for name, implementation in (
            ("current", actual + shared),
            ("old-condition", actual.replace(fixed,
                "personaFixUid == 0 || personaFixGid == 0 && childPid != -1") + shared),
            ("missing-persona-restore", actual.replace(
                "modifiedPersona->pspi_uid = personaFixUid;", "modifiedPersona->pspi_uid = 501;").replace(
                "modifiedPersona->pspi_gid = personaFixGid;", "modifiedPersona->pspi_gid = 501;") + shared),
            ("missing-flags-restore", actual.replace(
                "if (personaFixNeedsResume) posix_spawnattr_setflags(&attr, personaOriginalFlags);", "") + shared),
            ("missing-common-errno-restore", actual.replace("errno = spawnError;", "") + shared),
            ("missing-shared-errno-restore", actual + shared.replace("errno = spawnError;", "")),
        ):
            harness = directory / f"{name}.c"
            binary = directory / name
            harness.write_text(STUBS + enumerate_components + implementation + CASES)
            subprocess.run([
                compiler, "-std=gnu11", "-fblocks", "-O2", "-Werror=implicit-function-declaration",
                "-Wno-logical-op-parentheses", str(harness),
                str(environment), "-o", str(binary),
            ], check=True)
            result = subprocess.run([str(binary)], capture_output=True, text=True)
            if name == "current":
                if result.returncode:
                    raise SystemExit(result.stderr)
                print(result.stdout, end="")
            elif result.returncode == 0:
                raise SystemExit("Regression test incorrectly accepted " + name)
            else:
                print("PASS " + name + " rejected: " + result.stderr.strip())


if __name__ == "__main__":
    main()
