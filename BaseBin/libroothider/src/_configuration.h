#ifndef ZQBB_CONFIGURATION_H
#define ZQBB_CONFIGURATION_H

#include <xpc/xpc.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// 返回调用方持有的只读配置快照，使用后释放；fork/vfork 子进程重新建立缓存。
XPC_RETURNS_RETAINED xpc_object_t zqbb_read_dictionary(const char *path);

// 按可执行文件名读取布尔开关。
bool zqbb_dictionary_enabled(const char *name, const char *path);

// 按路径子串匹配已启用的系统白名单项。
bool zqbb_dictionary_matches_path(const char *path, const char *config);

// 保留旧配置的 boolValue 语义，并支持字典内的配置分组。
bool zqbb_dictionary_bool_value(const char *name, const char *section, const char *path);

#ifdef __cplusplus
}
#endif

#endif
