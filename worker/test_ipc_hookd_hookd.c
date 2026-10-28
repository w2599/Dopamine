#include <mach/mach.h>
#include <bsm/libbsm.h>
#include <xpc/xpc.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <setjmp.h>
#include "hookd_wire.h"

static union { uint64_t align; uint8_t bytes[HOOKD_MSG_MAX_SIZE + MAX_TRAILER_SIZE]; } request;
static jmp_buf done;
static int receives, sends, writes, protects, tasks, destroys, releases, allocations, reallocations;
static bool failAllocation, failTask, failSend, invalidAudit, allowOldServerBuffer, observeZeroLoop;
static size_t liveAllocations;
static int64_t replyResults[256];
static uint64_t receivedHooks, receivedFixups;
// 对真实分配注入失败并统计未释放对象。
static void *test_malloc(size_t size) {
    allocations++; if (failAllocation) return NULL; void *p = malloc(size); if (p) liveAllocations++; return p;
}
// 验证结果分配失败发生在任何任务修改之前。
static void *test_calloc(size_t count, size_t size) {
    void *p = test_malloc(count * size); if (p) memset(p, 0, count * size); return p;
}
// 限制旧实现的零前进循环，避免测试自己无限运行。
static void *test_realloc(void *p, size_t size) {
    assert(++reallocations < 10); if (!p) liveAllocations++; return realloc(p, size);
}
// 精确配对生产代码的分配。
static void test_free(void *p) { if (p) { assert(liveAllocations); liveAllocations--; free(p); } }
// 仅提供本机测试对象，绝不获取实际目标进程端口。
static kern_return_t test_task_for_pid(mach_port_t task, int pid, mach_port_name_t *port) {
    tasks++; *port = failTask ? MACH_PORT_NULL : 77; return failTask ? KERN_FAILURE : KERN_SUCCESS;
}
// 模拟端口引用计数。
static kern_return_t test_mod_refs(mach_port_t task, mach_port_t port, mach_port_right_t right, mach_port_delta_t delta) { return KERN_SUCCESS; }
// 记录任务端口释放。
static kern_return_t test_deallocate(mach_port_t task, mach_port_t port) { releases++; return KERN_SUCCESS; }
// 提供虚拟任务发送权。
static kern_return_t test_extract(mach_port_t task, mach_port_t name, mach_msg_type_name_t type, mach_port_t *out, mach_msg_type_name_t *right) {
    *out = 78; *right = MACH_MSG_TYPE_PORT_SEND; return KERN_SUCCESS;
}
// 记录权限修改，不调用真实 VM API。
static kern_return_t test_protect(vm_map_t task, vm_address_t address, vm_size_t size, boolean_t maximum, vm_prot_t protection) { protects++; return KERN_SUCCESS; }
// 校验实际 hook 数据指针和长度。
static kern_return_t test_write(vm_map_t task, vm_address_t address, vm_offset_t data, mach_msg_type_number_t size) {
    writes++; if (observeZeroLoop) return KERN_SUCCESS; assert(size == 3 && !memcmp((void *)data, "abc", 3)); return KERN_SUCCESS;
}
// 捕获 server 的发送内容，收到第二次 receive 时结束单轮。
static mach_msg_return_t test_mach_msg(mach_msg_header_t *msg, mach_msg_option_t options, mach_msg_size_t sendSize,
                                     mach_msg_size_t receiveSize, mach_port_name_t port, mach_msg_timeout_t timeout, mach_port_name_t notify) {
    if (options & MACH_RCV_MSG) {
        if (receives++) longjmp(done, 1);
        struct hookd_mach_msg *input = (void *)request.bytes;
        assert(receiveSize >= round_msg(input->hdr.msgh_size) + sizeof(mach_msg_audit_trailer_t));
        memcpy(msg, input, input->hdr.msgh_size);
        mach_msg_audit_trailer_t *trailer = (void *)((uint8_t *)msg + round_msg(msg->msgh_size));
        memset(trailer, 0, sizeof(*trailer)); trailer->msgh_trailer_type = MACH_MSG_TRAILER_FORMAT_0;
        trailer->msgh_trailer_size = sizeof(*trailer); trailer->msgh_audit.val[5] = invalidAudit ? 3 : 1;
        return KERN_SUCCESS;
    }
    sends++;
    struct hookd_mach_msg_reply *reply = (void *)msg;
    receivedHooks = reply->hookResultsCount; receivedFixups = reply->fixupResultsCount;
    assert(receivedHooks + receivedFixups <= 256);
    memcpy(replyResults, reply->data, (receivedHooks + receivedFixups) * sizeof(int64_t));
    return failSend ? MACH_SEND_TIMED_OUT : KERN_SUCCESS;
}
// 兼容旧实现的发送入口。
static mach_msg_return_t test_send(mach_msg_header_t *msg) { return test_mach_msg(msg, MACH_SEND_MSG, msg->msgh_size, 0, 0, 0, 0); }
// 只记录销毁次数，不接触任何内核端口。
static void test_destroy(mach_msg_header_t *msg) { destroys++; }
#define malloc test_malloc
#define calloc test_calloc
#define realloc test_realloc
#define free test_free
#define task_for_pid test_task_for_pid
#define mach_port_mod_refs test_mod_refs
#define mach_port_deallocate test_deallocate
#define mach_port_extract_right test_extract
#define vm_protect test_protect
#define vm_write test_write
#define mach_msg test_mach_msg
#define mach_msg_send test_send
#define mach_msg_destroy test_destroy
#include "hookd_production.inc"
#undef malloc
#undef calloc
#undef realloc
#undef free

// 重置一份合法的带不对齐 fixup 的请求。
static struct hookd_mach_msg *prepare(void) {
    memset(&request, 0, sizeof(request)); struct hookd_mach_msg *msg = (void *)request.bytes;
    msg->hdr.msgh_size = sizeof(*msg) + sizeof(struct hookd_encoded_hook) + 3 + sizeof(struct hookd_encoded_fixup);
    msg->hdr.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_PORT_SEND_ONCE, 0);
    msg->hdr.msgh_remote_port = 91; msg->hdr.msgh_id = 0x40000000; msg->clientPid = 123;
    msg->taskPortInClient = (mach_port_t)-1; msg->fixupsStartOff = sizeof(struct hookd_encoded_hook) + 3;
    struct hookd_encoded_hook hook = { .address = 0x1000, .dataSize = 3 };
    memcpy(msg->data, &hook, sizeof(hook)); memcpy(msg->data + sizeof(hook), "abc", 3);
    struct hookd_encoded_fixup fixup = { .address = 0x2000, .size = 0x1000, .set_maximum = false, .prot = VM_PROT_READ };
    memcpy(msg->data + msg->fixupsStartOff, &fixup, sizeof(fixup));
    return msg;
}
// 执行一轮真实 server_loop，检查所有结果和分配都已释放。
static void run(bool accepted) {
    receives = sends = writes = protects = tasks = destroys = releases = allocations = reallocations = 0;
    receivedHooks = receivedFixups = 0;
    if (setjmp(done) == 0) server_loop(92);
    assert(liveAllocations <= (allowOldServerBuffer ? 1 : 0));
    assert(sends == (accepted ? 1 : 0));
    if (accepted) {
        assert(writes == 1 && protects == 3 && tasks == 1 && receivedHooks == 1 && receivedFixups == 1);
        assert(replyResults[0] == 0 && replyResults[1] == 0);
    } else { assert(writes == 0 && protects == 0); }
}
// 覆盖完整头、超大长度、记录不完整和失败分配。
int main(int argc, char **argv) {
    const char *selected = argc > 1 ? argv[1] : "all";
    if (!strcmp(selected, "hookd-zero-progress")) {
        observeZeroLoop = true;
        struct hookd_mach_msg *msg = prepare(); struct hookd_encoded_hook hook = { .dataSize = (1ULL << 32) - sizeof(hook) };
        memcpy(msg->data, &hook, sizeof(hook));
        msg->fixupsStartOff = sizeof(hook); msg->hdr.msgh_size = sizeof(*msg) + sizeof(hook);
        run(false); puts("PASS zero-progress length rejected"); return 0;
    }
    if (!strcmp(selected, "hookd-leak")) {
        struct hookd_mach_msg *msg = prepare();
        memmove(msg->data + 1, msg->data, msg->hdr.msgh_size - sizeof(*msg));
        msg->hooksStartOff = 1; msg->fixupsStartOff++; msg->hdr.msgh_size++;
        allowOldServerBuffer = true; run(true); puts("PASS reply allocation released"); return 0;
    }
    prepare(); run(true); puts("PASS normal hooks and unaligned fixup");
    for (size_t i = 1; i < sizeof(struct hookd_encoded_hook); i++) {
        struct hookd_mach_msg *msg = prepare(); msg->fixupsStartOff = i; msg->hdr.msgh_size = sizeof(*msg) + i; run(false);
    }
    const uint64_t sizes[] = { 0, (1ULL << 32) - sizeof(struct hookd_encoded_hook), UINT64_MAX, 4 };
    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        struct hookd_mach_msg *msg = prepare(); struct hookd_encoded_hook hook = { .address = 0x1000, .dataSize = sizes[i] };
        memcpy(msg->data, &hook, sizeof(hook)); run(false);
    }
    struct hookd_mach_msg *msg = prepare(); msg->hdr.msgh_size--; run(false);
    msg = prepare(); msg->hooksStartOff = UINT64_MAX; run(false);
    msg = prepare(); msg->fixupsStartOff++; run(false);
    msg = prepare(); msg->hdr.msgh_size = sizeof(*msg) - 1; run(false);
    msg = prepare(); msg->hdr.msgh_bits |= MACH_MSGH_BITS_COMPLEX; run(false);
    msg = prepare(); struct hookd_encoded_hook hook = { .address = UINTPTR_MAX, .dataSize = 3 };
    memcpy(msg->data, &hook, sizeof(hook)); run(false);
    msg = prepare(); msg->data[msg->fixupsStartOff + offsetof(struct hookd_encoded_fixup, set_maximum)] = 2; run(false);
    prepare(); invalidAudit = true; run(false); invalidAudit = false;
    prepare(); failAllocation = true; run(false); assert(tasks == 0); failAllocation = false;
    prepare(); failTask = true; run(false); failTask = false;
    prepare(); failSend = true; run(true); assert(destroys == 2); failSend = false;
    for (int i = 0; i < 200; i++) { prepare(); run(true); }
    puts("PASS malformed records, allocation failures, send failures and repeated reply cleanup");
    return 0;
}
