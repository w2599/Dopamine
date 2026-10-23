#ifndef ZQBB_CONFIGURATION_H
#define ZQBB_CONFIGURATION_H

#include <xpc/xpc.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>

extern XPC_RETURNS_RETAINED xpc_object_t xpc_create_from_plist(const void *buf, size_t len);

// 从同一文件描述符读取配置，避免原子替换后的旧缓存和共享缓存竞争。
static inline xpc_object_t zqbb_read_dictionary(const char *path)
{
    if (!path) return NULL;
    int fd = open(path, O_RDONLY);
    if (fd < 0) return NULL;
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size <= 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        return NULL;
    }
    void *data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (data == MAP_FAILED) return NULL;
    xpc_object_t plist = xpc_create_from_plist(data, st.st_size);
    munmap(data, st.st_size);
    if (plist && xpc_get_type(plist) != XPC_TYPE_DICTIONARY) {
        xpc_release(plist);
        return NULL;
    }
    return plist;
}

// 按可执行文件名读取布尔开关。
static inline bool zqbb_dictionary_enabled(const char *name, const char *path)
{
    if (!name) return false;
    xpc_object_t plist = zqbb_read_dictionary(path);
    if (!plist) return false;
    bool enabled = xpc_dictionary_get_bool(plist, name);
    xpc_release(plist);
    return enabled;
}

// 按路径子串匹配已启用的系统白名单项。
static inline bool zqbb_dictionary_matches_path(const char *path, const char *config)
{
    if (!path) return false;
    xpc_object_t plist = zqbb_read_dictionary(config);
    if (!plist) return false;
    __block bool found = false;
    xpc_dictionary_apply(plist, ^bool(const char *key, xpc_object_t value) {
        if (*key && xpc_get_type(value) == XPC_TYPE_BOOL && xpc_bool_get_value(value) && strstr(path, key)) {
            found = true;
            return false;
        }
        return true;
    });
    xpc_release(plist);
    return found;
}
#endif
