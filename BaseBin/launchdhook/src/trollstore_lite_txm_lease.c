#include "trollstore_lite_txm.h"
#include <libjailbreak/txm_trust.h>
#include <libjailbreak/kernel.h>
#include <libroothider/log.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <dispatch/dispatch.h>

struct trollstore_lite_txm_lease {
    struct trollstore_lite_txm_lease *next;
    struct txm_trust_state state;
    uint64_t vnode;
    size_t holders;
    int fd;
};
static pthread_mutex_t gLeaseLock = PTHREAD_MUTEX_INITIALIZER;
// 两种启动路径均由退出事件持有租约，不依赖 check-in 或对应用暴露 IPC。
static struct trollstore_lite_txm_lease *gLeases;
#define TROLLSTORE_LITE_TXM_MAX_LEASES 512

struct trollstore_lite_txm_exit_watch {
    dispatch_source_t source;
    struct trollstore_lite_txm_session *session;
};

// 查找共享签名的租约，调用时必须持锁。
static struct trollstore_lite_txm_lease **lease_slot(uint64_t address)
{
    struct trollstore_lite_txm_lease **slot = &gLeases;
    while (*slot && (*slot)->state.address != address) slot = &(*slot)->next;
    return slot;
}

// 恢复成功后释放固定 vnode 的描述符；失败则保留状态供下次请求重试。
static int lease_restore(struct trollstore_lite_txm_lease **slot)
{
    struct trollstore_lite_txm_lease *lease = *slot;
    int status = txm_trust_restore(&lease->state);
    if (status) {
        JBLogError("TrollStoreLite TXM restore failed vnode=%llx status=%d", lease->vnode, status);
        return status;
    }
    *slot = lease->next;
    close(lease->fd);
    free(lease);
    return 0;
}

// 仅锁住内存状态转换，绝不持锁执行 F_ADDFILESIGS 或 spawn。
int trollstore_lite_txm_acquire(int fd, uint64_t vnode, uint64_t address,
                          struct trollstore_lite_txm_lease **out)
{
    *out = NULL;
    pthread_mutex_lock(&gLeaseLock);
    struct trollstore_lite_txm_lease **slot = lease_slot(address);
    int status = 0;
    if (*slot && (*slot)->holders == 0) {
        status = lease_restore(slot);
        if (!status) slot = lease_slot(address);
    }
    if (status == 0 && *slot) {
        if ((*slot)->vnode != vnode) status = ESTALE;
        else {
            (*slot)->holders++;
            *out = *slot;
        }
    } else if (status == 0) {
        // 恢复失败的记录也计入上限，防止持续失败耗尽 PID 1 的描述符。
        size_t count = 0;
        for (struct trollstore_lite_txm_lease *item = gLeases; item; item = item->next) count++;
        struct trollstore_lite_txm_lease *lease = count < TROLLSTORE_LITE_TXM_MAX_LEASES ? calloc(1, sizeof(*lease)) : NULL;
        if (!lease) status = count < TROLLSTORE_LITE_TXM_MAX_LEASES ? ENOMEM : ENOSPC;
        else {
            lease->fd = fd;
            lease->vnode = vnode;
            status = txm_trust_prepare(address, &lease->state);
            if (!lease->state.address) free(lease);
            else {
                fd = -1;
                lease->next = *slot;
                *slot = lease;
                if (status == 0) {
                    lease->holders = 1;
                    *out = lease;
                } else {
                    // 写入后回读失败也必须尝试回滚，不能丢失原值。
                    lease_restore(slot);
                }
            }
        }
    }
    pthread_mutex_unlock(&gLeaseLock);
    if (fd >= 0) close(fd);
    return status;
}

// 最后一个使用者退出后恢复签名；整个生命周期固定 vnode，避免地址被回收复用。
static int lease_release(struct trollstore_lite_txm_lease *lease)
{
    int status = 0;
    pthread_mutex_lock(&gLeaseLock);
    if (--lease->holders == 0) {
        status = lease_restore(lease_slot(lease->state.address));
    }
    pthread_mutex_unlock(&gLeaseLock);
    return status;
}

// 释放整组签名；部分恢复失败仍继续释放其余签名，并保留首个错误。
static int session_release(struct trollstore_lite_txm_session *session)
{
    int status = 0;
    while (session->count) {
        int result = lease_release(session->images[--session->count]);
        if (!status) status = result;
    }
    free(session);
    return status;
}

// 退出事件只取消监听，由取消回调统一释放一次。
static void process_exited(void *context)
{
    struct trollstore_lite_txm_exit_watch *watch = context;
    dispatch_source_cancel(watch->source);
}

// 确认退出事件不再访问上下文后，恢复签名并释放监听资源。
static void exit_watch_cancelled(void *context)
{
    struct trollstore_lite_txm_exit_watch *watch = context;
    session_release(watch->session);
    dispatch_release(watch->source);
    free(watch);
}

// 成功启动后维持主程序与同包库的信任；最后一个使用者退出后才回滚。
int trollstore_lite_txm_end(struct trollstore_lite_txm_session *session, pid_t pid)
{
    if (!session) return 0;
    if (pid <= 0) return session_release(session);
    if (!session->count) { free(session); return EINVAL; }
    struct trollstore_lite_txm_lease *lease = session->images[0];
    uint64_t proc = proc_find(pid);
    int status = proc ? txm_trust_validate_process(proc, lease->vnode, lease->state.address) : ESRCH;
    if (proc) proc_rele(proc);
    if (!status) {
        struct trollstore_lite_txm_exit_watch *watch = calloc(1, sizeof(*watch));
        if (!watch) status = ENOMEM;
        else {
            watch->session = session;
            watch->source = dispatch_source_create(DISPATCH_SOURCE_TYPE_PROC, (uintptr_t)pid,
                DISPATCH_PROC_EXIT, dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0));
            // 必须同时检查 PID 和创建结果，禁止对 NULL 调用任何 dispatch 接口。
            if (!watch->source) { free(watch); status = ENOMEM; }
            else {
                dispatch_set_context(watch->source, watch);
                dispatch_source_set_event_handler_f(watch->source, process_exited);
                dispatch_source_set_cancel_handler_f(watch->source, exit_watch_cancelled);
                dispatch_resume(watch->source);
                return 0;
            }
        }
    }
    session_release(session);
    return status;
}
