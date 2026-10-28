#include <mach/mach.h>
#include <xpc/xpc.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <fcntl.h>
#include "ipc_types.inc"

static bool allowReply;
static int calls, replies, handlerFD = -1;
static xpc_object_t lastReply;
extern void xpc_dictionary_set_mach_recv(xpc_object_t, const char *, mach_port_t);
extern mach_port_t xpc_dictionary_extract_mach_recv(xpc_object_t, const char *);
// 不拦截正常 IPC 域。
static bool roothide_handle_xpc_msg(xpc_object_t message) { return false; }
// 测试消息没有真实发送方，使用确定的审计标记。
static void test_audit(xpc_object_t message, audit_token_t *token) { token->val[0] = 123; }
// 无回复场景调用真实 libxpc，正常场景只替换传输上下文。
static xpc_object_t test_create_reply(xpc_object_t message) {
    return allowReply ? xpc_dictionary_create(NULL, NULL, 0) : xpc_dictionary_create_reply(message);
}
// 捕获回复内容，不发送外部 IPC。
static int test_reply(xpc_object_t reply) {
    replies++; if (lastReply) xpc_release(lastReply); lastReply = xpc_retain(reply); return 0;
}
#define xpc_dictionary_get_audit_token test_audit
#define xpc_dictionary_create_reply test_create_reply
#define xpc_pipe_routine_reply test_reply
#include "ipc_production.inc"
// 未使用的 action 只记录调用。
static int test_unused(void) { calls++; return 0; }
// 允许本地测试身份。
static bool systemwide_domain_allowed(audit_token_t token) { return true; }
// 检查缺少显式终止项的 settings action 仍正确传递输出槽。
static int jbsettings_get(const char *key, xpc_object_t *value) {
    calls++; assert(key && !strcmp(key, "setting")); *value = xpc_uint64_create(42); return 7;
}
// 检查 persona action 的四个参数。
static int systemwide_persona_fix(audit_token_t *token, uint64_t pid, uint64_t uid, uint64_t gid) {
    calls++; assert(token->val[0] == 123 && pid == 45 && uid == 501 && gid == 502); return 0;
}
// 检查 DATA 的长度槽之后仍可传递 attach。
static int systemwide_trust_file(audit_token_t *token, uint64_t fd, const void *bytes, size_t size, bool attach) {
    calls++; assert(token->val[0] == 123 && fd == 17 && size == 3 && !memcmp(bytes, "abc", 3) && attach); return 0;
}
#include "ipc_table.inc"
static struct jbserver_impl server = { .domains = (struct jbserver_domain *[]){ &gSystemwideDomain, NULL } };
// 构造独立消息，确保不沿用上个请求的数据。
static xpc_object_t message(uint64_t action) {
    xpc_object_t result = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_uint64(result, "jb-domain", 1);
    xpc_dictionary_set_uint64(result, "action", action);
    return result;
}
// 同时验证 DATA 输出长度以及其后的输入 FD 清理。
static int data_output(void **bytes, size_t *size, int fd) {
    calls++; handlerFD = fd; assert(fd >= 0 && fcntl(fd, F_GETFD) != -1); *bytes = strdup("xyz"); *size = 3; return 0;
}
// 执行当前模块回归；旧提交可选择单项复现。
int main(int argc, char **argv) {
    const char *selected = argc > 1 ? argv[1] : "all";
    bool all = !strcmp(selected, "all");
    if (all || !strcmp(selected, "ipc-missing-reply")) {
        allowReply = false; calls = 0; xpc_object_t request = message(1);
        assert(jbserver_received_xpc_message(&server, request) != 0); assert(calls == 0 && replies == 0);
        xpc_release(request); puts("PASS real libxpc missing reply rejected before handler");
    }
    allowReply = true;
    if (all || !strcmp(selected, "ipc-settings")) {
        xpc_object_t request = message(7); xpc_dictionary_set_string(request, "key", "setting");
        assert(jbserver_received_xpc_message(&server, request) == 0);
        assert(xpc_dictionary_get_uint64(lastReply, "value") == 42 && xpc_dictionary_get_int64(lastReply, "result") == 7);
        xpc_release(request); puts("PASS actual settings table terminator");
    }
    if (all || !strcmp(selected, "ipc-persona")) {
        xpc_object_t request = message(8);
        xpc_dictionary_set_uint64(request, "child-pid", 45); xpc_dictionary_set_uint64(request, "overwrite-uid", 501);
        xpc_dictionary_set_uint64(request, "overwrite-gid", 502);
        assert(jbserver_received_xpc_message(&server, request) == 0); xpc_release(request);
        puts("PASS actual persona table terminator");
    }
    if (all || !strcmp(selected, "ipc-data-slot")) {
        xpc_object_t request = message(3); xpc_dictionary_set_uint64(request, "fd", 17);
        xpc_dictionary_set_data(request, "siginfo", "abc", 3); xpc_dictionary_set_bool(request, "attach", true);
        assert(jbserver_received_xpc_message(&server, request) == 0); xpc_release(request);
        puts("PASS DATA length and following attach slots");
    }
#ifdef JBSERVER_MAX_ARGS
    if (all) {
        struct jbserver_action saved = gSystemwideDomain.actions[0];
        gSystemwideDomain.actions[0] = (struct jbserver_action){ .handler = data_output, .args = {
            { "bytes", JBS_TYPE_DATA, true }, { "fd", JBS_TYPE_FD, false } } };
        xpc_object_t request = message(1); int fds[2]; assert(pipe(fds) == 0);
        xpc_dictionary_set_fd(request, "fd", fds[0]);
        assert(jbserver_received_xpc_message(&server, request) == 0);
        size_t size = 0; const void *data = xpc_dictionary_get_data(lastReply, "bytes", &size);
        assert(size == 3 && !memcmp(data, "xyz", 3)); assert(fcntl(handlerFD, F_GETFD) == -1); close(fds[0]); close(fds[1]); xpc_release(request);
        gSystemwideDomain.actions[0].handler = test_unused;
        for (size_t i = 0; i < JBSERVER_MAX_ARGS; i++) gSystemwideDomain.actions[0].args[i] = (jbserver_arg){ "slot", JBS_TYPE_UINT64, false };
        request = message(1); int before = calls;
        assert(jbserver_received_xpc_message(&server, request) == 0 && calls == before + 1);
        gSystemwideDomain.actions[0].args[7].type = JBS_TYPE_DATA; before = calls;
        assert(jbserver_received_xpc_message(&server, request) != 0 && calls == before);
        gSystemwideDomain.actions[0] = saved; xpc_release(request);
        puts("PASS DATA output, full eight slots, and overflow rejection");
    }
#endif
    if (lastReply) xpc_release(lastReply);
    return 0;
}
