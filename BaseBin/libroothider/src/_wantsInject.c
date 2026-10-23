#include "_configuration.h"

// 查询用户是否允许指定可执行文件注入。
bool zqbb_wantsInject(const char *execName, const char *injectPath)
{
    return zqbb_dictionary_enabled(execName, injectPath);
}
