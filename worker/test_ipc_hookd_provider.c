#include <mach/mach.h>
#include <mach/mig.h>
#include <bsm/libbsm.h>
#include <xpc/xpc.h>
#include <spawn.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <assert.h>
#if __has_feature(address_sanitizer)
#include <sanitizer/asan_interface.h>
#endif
#include "hookd_wire.h"

int (*hookd_send_msg)(struct hookd_mach_msg *, struct hookd_mach_msg_reply *);
static mach_port_t checkinPort, serverPort;
static int fault, spawned, attrsCreated, attrsDestroyed, killed, waited, sendCalls, receiveCalls;
static int childState; // 0 运行，1 等待退出，2 已退出，3 非子进程。
static bool checkinPending, reenter, teardownDuringSend;
void hookd_provider_teardown(void);
static mach_port_t ports[64];
static size_t portCount;
static int launchd_hookd_send_msg(struct hookd_mach_msg *, struct hookd_mach_msg_reply *);
// 真实分配仅限本进程私有端口，记录以检查所有权清理。
static kern_return_t test_allocate(ipc_space_t task, mach_port_right_t right, mach_port_name_t *name) {
    if (fault == 1) return KERN_RESOURCE_SHORTAGE;
    kern_return_t kr = mach_port_allocate(task, right, name);
    if (kr == KERN_SUCCESS) { assert(portCount < 64); ports[portCount++] = *name; }
    return kr;
}
// 注入 make-send 失败。
static kern_return_t test_insert(ipc_space_t task, mach_port_name_t name, mach_port_t right, mach_msg_type_name_t type) {
    return fault == 2 ? KERN_INVALID_RIGHT : mach_port_insert_right(task, name, right, type);
}
// 使用真实属性对象，测试初始化失败不触发销毁。
static int test_attr_init(posix_spawnattr_t *attr) { if (fault == 3) return ENOMEM; attrsCreated++; return posix_spawnattr_init(attr); }
// 统计属性对象释放。
static int test_attr_destroy(posix_spawnattr_t *attr) { attrsDestroyed++; return posix_spawnattr_destroy(attr); }
// 捕获启动握手端口，不启动外部进程。
static int test_registered(posix_spawnattr_t *attr, mach_port_t array[], uint32_t count) {
    assert(count == 3); checkinPort = array[2]; return fault == 4 ? EINVAL : 0;
}
// 用真实 Mach 发送当前进程身份的 checkin，同时可触发重入。
static int test_spawn(pid_t *pid, const char *path, const posix_spawn_file_actions_t *actions,
                      const posix_spawnattr_t *attr, char *const argv[], char *const env[]) {
    spawned++; *pid = getpid();
    if (fault == 5) { *pid = 99999; return ENOENT; }
    if (fault == 6) { *pid = 0; return 0; }
    if (reenter) {
        struct hookd_mach_msg request = { .hdr.msgh_size = sizeof(request) };
        struct hookd_mach_msg_reply reply = { .hdr.msgh_size = sizeof(reply) };
        assert(launchd_hookd_send_msg(&request, &reply) == EBUSY);
    }
    childState = 0; checkinPending = true;
    if (fault == 7) return 0;
    if (MACH_PORT_VALID(serverPort)) mach_port_destroy(mach_task_self(), serverPort);
    assert(mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &serverPort) == KERN_SUCCESS);
    mach_msg_header_t message = { .msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND),
        .msgh_size = sizeof(message), .msgh_remote_port = checkinPort, .msgh_local_port = serverPort, .msgh_id = 0x40000000 };
    if (fault == 8) message.msgh_id = 0;
    assert(mach_msg(&message, MACH_SEND_MSG | MACH_SEND_TIMEOUT, message.msgh_size, 0, 0, 10, 0) == KERN_SUCCESS);
    if (fault == 9) *pid = getpid() + 1;
    return 0;
}
// 模拟 waitpid，不等待或探测任何外部进程。
static int test_waitpid(pid_t pid, int *status, int options) {
    assert(options == WNOHANG); waited++;
    if (childState == 0 || childState == 1) return 0;
    if (childState == 2) return pid;
    errno = ECHILD; return -1;
}
// 不执行真实 kill，只将测试子进程置为待回收状态。
static int test_kill(pid_t pid, int signal) { assert(pid > 0 && signal == SIGKILL && (childState == 0 || childState == 1)); killed++; childState = 1; return 0; }
// 旧版本的无界退出等待必须被测试发现。
static int test_wait_for_exit(pid_t pid) { assert(!"unbounded wait used"); return 0; }
// checkin 使用真实内核 trailer，转发由本地桩注入超时和格式错误。
static mach_msg_return_t test_mach_msg(mach_msg_header_t *msg, mach_msg_option_t options, mach_msg_size_t sendSize,
                                     mach_msg_size_t receiveSize, mach_port_name_t port, mach_msg_timeout_t timeout, mach_port_name_t notify) {
    if (checkinPending && (options & MACH_RCV_MSG) && port == checkinPort) {
#if __has_feature(address_sanitizer)
        assert(__asan_region_is_poisoned(msg, receiveSize) == NULL);
#endif
        assert(options & MACH_RCV_TIMEOUT);
        checkinPending = false;
        return mach_msg(msg, options, sendSize, receiveSize, port, fault == 7 ? 1 : timeout, notify);
    }
    if (options & MACH_SEND_MSG) {
        if (teardownDuringSend) hookd_provider_teardown();
        sendCalls++; assert((options & MACH_SEND_TIMEOUT) && timeout > 0);
        return fault == 10 ? MACH_SEND_TIMED_OUT : KERN_SUCCESS;
    }
    receiveCalls++; assert((options & MACH_RCV_TIMEOUT) && timeout > 0);
    if (fault == 11) return MACH_RCV_TIMED_OUT;
    struct hookd_mach_msg_reply *reply = (void *)msg;
    memset(reply, 0, sizeof(*reply)); reply->hdr.msgh_size = sizeof(*reply);
    reply->hdr.msgh_id = 0x40000000 + 100; reply->hdr.msgh_local_port = port;
    if (fault == 12) reply->hookResultsCount = UINT64_MAX;
    if (fault == 13) reply->hdr.msgh_size = sizeof(mach_msg_header_t);
    if (fault == 14) reply->hdr.msgh_id = 17;
    return KERN_SUCCESS;
}
#define JBROOT_PATH(x) "/test/hookd"
#define posix_spawnattr_init test_attr_init
#define posix_spawnattr_destroy test_attr_destroy
#define posix_spawnattr_set_registered_ports_np test_registered
#define posix_spawn test_spawn
#define mach_port_allocate test_allocate
#define mach_port_insert_right test_insert
#define mach_msg test_mach_msg
#define waitpid_inline test_waitpid
#define waitpid test_waitpid
#define kill test_kill
#define cmd_wait_for_exit test_wait_for_exit
#include "provider_production.inc"
#undef mach_port_allocate
#undef mach_port_insert_right
#undef mach_msg
#undef waitpid
#undef kill

// 检查所有本轮创建的接收权均被销毁。
static void check_cleanup(void) {
    for (size_t i = 0; i < portCount; i++) {
        mach_port_type_t type = 0;
        kern_return_t kr = mach_port_type(mach_task_self(), ports[i], &type);
        assert(kr == KERN_INVALID_NAME || !(type & (MACH_PORT_TYPE_RECEIVE | MACH_PORT_TYPE_SEND)));
    }
    assert(attrsCreated == attrsDestroyed);
}
// 清理测试自建的假服务端口和全局状态。
static void reset(int selectedFault) {
    if (MACH_PORT_VALID(gHookdPort)) mach_port_deallocate(mach_task_self(), gHookdPort);
    if (MACH_PORT_VALID(serverPort)) mach_port_destroy(mach_task_self(), serverPort);
    gHookdPort = serverPort = MACH_PORT_NULL; gHookdPid = -1;
    fault = selectedFault; spawned = attrsCreated = attrsDestroyed = killed = waited = sendCalls = receiveCalls = 0;
    portCount = 0; childState = 0; checkinPending = reenter = teardownDuringSend = false;
    hookd_provider_init();
}
// 调用真实转发函数，缓冲容量与生产客户端相同。
static int forward(void) {
    struct hookd_mach_msg request = { .hdr.msgh_size = sizeof(request) };
    union { uint64_t align; uint8_t bytes[HOOKD_MSG_MAX_SIZE + MAX_TRAILER_SIZE]; } buffer = { 0 };
    struct hookd_mach_msg_reply *reply = (void *)buffer.bytes;
    reply->hdr.msgh_size = sizeof(buffer);
    return launchd_hookd_send_msg(&request, reply);
}
// 并发调用不得进入已持有的生命周期状态。
static void *concurrent_forward(void *result) { *(int *)result = forward(); return NULL; }
// 覆盖真实 trailer、初始化失败、超时恢复及 PID 归属。
int main(int argc, char **argv) {
    const char *selected = argc > 1 ? argv[1] : "all";
    if (!strcmp(selected, "provider-checkin")) {
        reset(0); assert(hookd_start(&gHookdPid, &gHookdPort) == 0);
        assert(gHookdPid == getpid() && MACH_PORT_VALID(gHookdPort)); check_cleanup();
        reset(0); puts("PASS real Mach checkin trailer and resources"); return 0;
    }
    reset(0); reenter = true; assert(forward() == 0); assert(spawned == 1); check_cleanup();
    assert(forward() == 0 && spawned == 1); check_cleanup();
    puts("PASS real Mach checkin, forwarding and same-thread reentry");
    for (int f = 1; f <= 9; f++) {
        reset(f); assert(forward() != 0); check_cleanup();
        if (f <= 6) assert(gHookdPid == -1 && killed == 0);
        else { assert(killed == 1 && gHookdPid > 0); childState = 2; fault = 0; assert(forward() == 0); }
    }
    for (int f = 10; f <= 14; f++) {
        reset(f); assert(forward() != 0); assert(killed == 1 && spawned == 1 && gHookdPid == getpid());
        check_cleanup(); assert(forward() == EAGAIN && spawned == 1 && killed == 1);
        childState = 2; fault = 0; assert(forward() == 0 && spawned == 2); check_cleanup();
    }
    reset(0); gHookdPid = 99999; childState = 3; assert(forward() == 0); assert(killed == 0 && spawned == 1);
    childState = 2; hookd_provider_teardown(); assert(gHookdPid == -1 && gHookdPort == MACH_PORT_NULL); check_cleanup();
    reset(0);
    #ifdef IPC_HOOKD_FIXED_PROVIDER
    pthread_t thread; int concurrentResult = 0;
    assert(pthread_mutex_lock(&gHookdLock) == 0);
    assert(pthread_create(&thread, NULL, concurrent_forward, &concurrentResult) == 0);
    assert(pthread_join(thread, NULL) == 0 && concurrentResult == EBUSY);
    assert(pthread_mutex_unlock(&gHookdLock) == 0);
    teardownDuringSend = true; assert(forward() == 0);
    assert(killed == 1 && gHookdPort == MACH_PORT_NULL && forward() == ECANCELED);
    check_cleanup();
    #endif
    reset(0); puts("PASS initialization errors, bounded recovery, PID ownership and pending teardown");
    return 0;
}
