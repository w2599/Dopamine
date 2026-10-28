#include "_zqbb.h"
#include <libroothider/_configuration.h>
#include <limits.h>
#include <string.h>

// 查询用户是否允许指定可执行文件注入。
bool zqbb_wantInject(const char *execName, const char *injectPath)
{
    return zqbb_dictionary_enabled(execName, injectPath);
}

// 查询路径是否命中系统注入白名单。
bool zqbb_isWhiteList(const char *path)
{
    return zqbb_dictionary_matches_path(path, JBROOT_PATH("/var/mobile/Library/RootHide/cn.zqbb.inject.system.plist"));
}

// 返回进程专用的附加内存额度，缺省为 10 MB。
int zqbb_getJetsamAddend(const char *path)
{
    if (!path) return 10;
    xpc_object_t plist = zqbb_read_dictionary(JBROOT_PATH("/var/mobile/Library/RootHide/cn.zqbb.jetsam.addend.plist"));
    if (!plist) return 10;
    __block int result = 10;
    xpc_dictionary_apply(plist, ^bool(const char *key, xpc_object_t value) {
        if (*key && xpc_get_type(value) == XPC_TYPE_INT64) {
            int64_t amount = xpc_int64_get_value(value);
            if (amount > 0 && amount <= INT_MAX && strstr(path, key)) {
                result = (int)amount;
                return false;
            }
        }
        return true;
    });
    xpc_release(plist);
    return result;
}
