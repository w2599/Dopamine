#include "_configuration.h"

// 查询路径是否命中系统注入白名单。
bool zqbb_isWhiteListForSystem(const char *path, const char *injectSystemPath)
{
    return zqbb_dictionary_matches_path(path, injectSystemPath);
}
