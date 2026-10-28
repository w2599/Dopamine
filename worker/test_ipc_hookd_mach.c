#include <mach/mach.h>
#include <bsm/libbsm.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include "hookd_wire.h"
struct siginfo { uint64_t unused; };
#include "mach_types.inc"

static int forwarded, sent;
static uint64_t replyStatus;
static bool failAllocation, oversizedReply;
// 未覆盖的其他 action 不应被调用。
static int systemwide_process_checkin(audit_token_t *token, char **root, char **uuid, char **sandbox, bool *debugged, bool *adhoc) { abort(); }
// 未覆盖的 fork action 不应被调用。
static int systemwide_fork_fix(audit_token_t *token, uint64_t pid) { abort(); }
// 未覆盖的 trust action 不应被调用。
static int systemwide_trust_file(audit_token_t *token, int fd, struct siginfo *info, size_t size, bool attach) { abort(); }
// 放行本机测试身份。
static bool systemwide_domain_allowed(audit_token_t token) { return true; }
// 默认客户端入口不得被 launchd 路由回自身。
static int jbclient_mach_hookd_send_msg(struct hookd_mach_msg *request, struct hookd_mach_msg_reply *reply) { abort(); }
// 检查外层调用是否清理端口头并覆盖伪造的 client PID。
static int forward(struct hookd_mach_msg *request, struct hookd_mach_msg_reply *reply) {
    forwarded++; assert(request->clientPid == 123 && request->hdr.msgh_bits == 0 && request->hdr.msgh_remote_port == 0);
    memset(reply, 0, sizeof(*reply)); reply->hdr.msgh_size = oversizedReply ? HOOKD_MSG_MAX_SIZE + 1 : sizeof(*reply); return 0;
}
int (*hookd_send_msg)(struct hookd_mach_msg *, struct hookd_mach_msg_reply *) = forward;
// 捕获外层结果，不进行任何 IPC 发送。
static int jbserver_send_mach_reply(mach_msg_header_t *header, void *data) {
    assert(data); sent++; struct jbserver_mach_msg_reply *reply = data; replyStatus = reply->status; return 0;
}
// 注入外层回复分配失败。
static void *test_malloc(size_t size) { return failAllocation ? NULL : malloc(size); }
#define malloc test_malloc
#define JBLogDebug(...) ((void)0)
#include "mach_production.inc"
#undef malloc

// 创建精确大小的缓冲，使截断 header 的读取能够被 ASan 检测。
static struct jbserver_mach_msg_hookd_send_msg *message(size_t payloadSize) {
    struct jbserver_mach_msg_hookd_send_msg *msg = calloc(1, sizeof(*msg) + payloadSize);
    assert(msg); msg->base.hdr.msgh_size = sizeof(*msg) + payloadSize; msg->base.action = JBSERVER_MACH_HOOKD_SEND_MSG;
    if (payloadSize >= sizeof(struct hookd_mach_msg)) {
        struct hookd_mach_msg *inner = (void *)msg->hookdMsg;
        inner->hdr.msgh_size = payloadSize; inner->hdr.msgh_bits = UINT32_MAX; inner->hdr.msgh_remote_port = 99; inner->clientPid = -1;
    }
    return msg;
}
// 验证嵌套长度、默认入口、回复容量和分配错误。
int main(int argc, char **argv) {
    audit_token_t token = { 0 }; token.val[5] = 123;
    for (size_t n = 0; n < sizeof(struct hookd_mach_msg); n++) {
        struct jbserver_mach_msg_hookd_send_msg *msg = message(n);
        assert(jbserver_received_mach_message(&token, &msg->base) != 0); free(msg);
    }
    assert(forwarded == 0 && sent == 0);
    for (size_t n = 0; n < sizeof(struct hookd_mach_msg); n++) {
        struct jbserver_mach_msg_hookd_send_msg *msg = message(sizeof(struct hookd_mach_msg));
        ((struct hookd_mach_msg *)msg->hookdMsg)->hdr.msgh_size = n;
        assert(jbserver_received_mach_message(&token, &msg->base) != 0); free(msg);
    }
    struct jbserver_mach_msg_hookd_send_msg *msg = message(sizeof(struct hookd_mach_msg));
    ((struct hookd_mach_msg *)msg->hookdMsg)->hdr.msgh_size++;
    assert(jbserver_received_mach_message(&token, &msg->base) != 0); free(msg);
    msg = message(sizeof(struct hookd_mach_msg));
    assert(jbserver_received_mach_message(&token, &msg->base) == 0 && replyStatus == 0 && forwarded == 1); free(msg);
    msg = message(sizeof(struct hookd_mach_msg)); hookd_send_msg = jbclient_mach_hookd_send_msg;
    assert(jbserver_received_mach_message(&token, &msg->base) == 0 && replyStatus == ENOTSUP); free(msg);
    msg = message(sizeof(struct hookd_mach_msg)); hookd_send_msg = NULL;
    assert(jbserver_received_mach_message(&token, &msg->base) == 0 && replyStatus == ENOTSUP); free(msg);
    msg = message(sizeof(struct hookd_mach_msg)); hookd_send_msg = forward; oversizedReply = true;
    assert(jbserver_received_mach_message(&token, &msg->base) == 0 && replyStatus == EPROTO); free(msg);
    msg = message(sizeof(struct hookd_mach_msg)); oversizedReply = false; failAllocation = true;
    int sentBefore = sent; assert(jbserver_received_mach_message(&token, &msg->base) != 0 && sent == sentBefore); free(msg);
    puts("PASS nested Mach headers, unavailable provider, reply bounds and allocation failure");
    return 0;
}
