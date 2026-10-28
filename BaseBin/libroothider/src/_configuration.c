#include "_configuration.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

extern XPC_RETURNS_RETAINED xpc_object_t xpc_create_from_plist(const void *buf, size_t len);

#define ZQBB_CONFIGURATION_CACHE_CAPACITY 64

typedef struct {
    char *path;
    struct stat observed;
    xpc_object_t snapshot;
    uint64_t lastAccess;
} zqbb_configuration_entry;

typedef struct {
    pid_t owner;
    pthread_mutex_t lock;
    uint64_t access;
    zqbb_configuration_entry entries[ZQBB_CONFIGURATION_CACHE_CAPACITY];
} zqbb_configuration_state;

_Static_assert(ATOMIC_POINTER_LOCK_FREE == 2, "Configuration state requires lock-free pointers");
static _Atomic(zqbb_configuration_state *) configurationState;

// 子进程只发布全新状态，不访问或释放可能正在修改的继承缓存。
static zqbb_configuration_state *zqbb_configuration_current(void)
{
    pid_t owner = getpid();
    zqbb_configuration_state *state = atomic_load_explicit(&configurationState, memory_order_acquire);
    if (state && state->owner == owner) return state;

    zqbb_configuration_state *fresh = calloc(1, sizeof(*fresh));
    if (!fresh) return NULL;
    fresh->owner = owner;
    if (pthread_mutex_init(&fresh->lock, NULL) != 0) {
        free(fresh);
        return NULL;
    }
    if (atomic_compare_exchange_strong_explicit(&configurationState, &state, fresh,
                                                memory_order_acq_rel, memory_order_acquire)) {
        // 继承状态可能含悬空成员；留给进程退出回收，不能遍历清理。
        return fresh;
    }
    pthread_mutex_destroy(&fresh->lock);
    free(fresh);
    // 只有本进程的初始化线程会替换指针，失败说明它已发布完整状态。
    return state;
}

// 同时识别原子替换、原地修改和时间回退。
static bool zqbb_configuration_same_file(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
           a->st_mode == b->st_mode && a->st_size == b->st_size &&
           a->st_mtimespec.tv_sec == b->st_mtimespec.tv_sec &&
           a->st_mtimespec.tv_nsec == b->st_mtimespec.tv_nsec &&
           a->st_ctimespec.tv_sec == b->st_ctimespec.tv_sec &&
           a->st_ctimespec.tv_nsec == b->st_ctimespec.tv_nsec;
}

// 从同一描述符读取完整文件，读期间发生修改时留待下次重试。
static xpc_object_t zqbb_configuration_load(const char *path, struct stat *observed, bool *stable)
{
    *stable = false;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) return NULL;

    struct stat before;
    if (fstat(fd, &before) != 0) {
        close(fd);
        return NULL;
    }
    if (!S_ISREG(before.st_mode) || before.st_size <= 0 || (uint64_t)before.st_size > SIZE_MAX) {
        *observed = before;
        *stable = true;
        close(fd);
        return NULL;
    }

    size_t length = (size_t)before.st_size;
    void *data = malloc(length);
    if (!data) {
        close(fd);
        return NULL;
    }
    size_t offset = 0;
    while (offset < length) {
        ssize_t count = read(fd, (char *)data + offset, length - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) break;
        offset += (size_t)count;
    }
    struct stat after;
    bool complete = offset == length && fstat(fd, &after) == 0 &&
                    zqbb_configuration_same_file(&before, &after);
    close(fd);
    xpc_object_t plist = NULL;
    if (complete) {
        *observed = after;
        *stable = true;
        plist = xpc_create_from_plist(data, length);
        if (plist && xpc_get_type(plist) != XPC_TYPE_DICTIONARY) {
            xpc_release(plist);
            plist = NULL;
        }
    }
    free(data);
    return plist;
}

// 释放缓存持有的引用，调用方已取得的快照仍然有效。
static void zqbb_configuration_clear(zqbb_configuration_entry *entry)
{
    free(entry->path);
    if (entry->snapshot) xpc_release(entry->snapshot);
    memset(entry, 0, sizeof(*entry));
}

// 锁内检查文件版本并发布快照，坏文件保留上一份有效配置。
static xpc_object_t zqbb_configuration_copy_locked(zqbb_configuration_state *state, const char *path)
{
    zqbb_configuration_entry *entry = NULL;
    zqbb_configuration_entry *victim = &state->entries[0];
    for (size_t i = 0; i < ZQBB_CONFIGURATION_CACHE_CAPACITY; i++) {
        zqbb_configuration_entry *candidate = &state->entries[i];
        if (candidate->path && strcmp(candidate->path, path) == 0) entry = candidate;
        if (!candidate->path || (victim->path && candidate->lastAccess < victim->lastAccess)) victim = candidate;
    }

    struct stat current;
    if (stat(path, &current) != 0) {
        if (entry && (errno == ENOENT || errno == ENOTDIR)) {
            zqbb_configuration_clear(entry);
            return NULL;
        }
        return entry && entry->snapshot ? xpc_retain(entry->snapshot) : NULL;
    }
    if (entry) {
        entry->lastAccess = ++state->access;
        if (zqbb_configuration_same_file(&current, &entry->observed)) {
            return entry->snapshot ? xpc_retain(entry->snapshot) : NULL;
        }
    }

    struct stat observed;
    bool stable;
    xpc_object_t snapshot = zqbb_configuration_load(path, &observed, &stable);
    if (stable) {
        if (!entry) {
            char *storedPath = strdup(path);
            if (!storedPath) return snapshot;
            entry = victim;
            zqbb_configuration_clear(entry);
            entry->path = storedPath;
        }
        entry->observed = observed;
        entry->lastAccess = ++state->access;
        if (snapshot) {
            if (entry->snapshot) xpc_release(entry->snapshot);
            entry->snapshot = snapshot;
        }
        return entry->snapshot ? xpc_retain(entry->snapshot) : NULL;
    }
    return entry && entry->snapshot ? xpc_retain(entry->snapshot) : NULL;
}

// 每次返回独立引用，并保留调用前的 errno。
xpc_object_t zqbb_read_dictionary(const char *path)
{
    if (!path) return NULL;
    int savedErrno = errno;
    zqbb_configuration_state *state = zqbb_configuration_current();
    xpc_object_t snapshot;
    if (state) {
        pthread_mutex_lock(&state->lock);
        snapshot = zqbb_configuration_copy_locked(state, path);
        pthread_mutex_unlock(&state->lock);
    }
    else {
        struct stat observed;
        bool stable;
        snapshot = zqbb_configuration_load(path, &observed, &stable);
    }
    errno = savedErrno;
    return snapshot;
}

// 跳过 NSString.boolValue 接受的 UTF-8 空白，不依赖进程 locale。
static const char *zqbb_configuration_skip_space(const char *string)
{
    const unsigned char *p = (const unsigned char *)string;
    while (*p) {
        if (*p == ' ' || *p == '\t') p++;
        else if (p[0] == 0xC2 && p[1] == 0xA0) p += 2;
        else if (p[0] == 0xE1 && p[1] == 0x9A && p[2] == 0x80) p += 3;
        else if (p[0] == 0xE2 && p[1] == 0x80 &&
                 ((p[2] >= 0x80 && p[2] <= 0x8B) || p[2] == 0xAF)) p += 3;
        else if (p[0] == 0xE2 && p[1] == 0x81 && p[2] == 0x9F) p += 3;
        else if (p[0] == 0xE3 && p[1] == 0x80 && p[2] == 0x80) p += 3;
        else break;
    }
    return (const char *)p;
}

// 只识别布尔首字母和十进制前缀，避免 strtoll 额外跳过换行。
static bool zqbb_configuration_string_bool(const char *string)
{
    string = zqbb_configuration_skip_space(string);
    if (*string == 'Y' || *string == 'y' || *string == 'T' || *string == 't') return true;
    if (*string == '+' || *string == '-') string++;
    while (*string == '0') string++;
    return *string >= '1' && *string <= '9';
}

// 按可执行文件名读取布尔开关。
bool zqbb_dictionary_enabled(const char *name, const char *path)
{
    if (!name) return false;
    xpc_object_t plist = zqbb_read_dictionary(path);
    if (!plist) return false;
    bool enabled = xpc_dictionary_get_bool(plist, name);
    xpc_release(plist);
    return enabled;
}

// 按路径子串匹配已启用的系统白名单项。
bool zqbb_dictionary_matches_path(const char *path, const char *config)
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

// 兼容旧版 NSDictionary 中布尔、数字和字符串的 boolValue。
bool zqbb_dictionary_bool_value(const char *name, const char *section, const char *path)
{
    if (!name) return false;
    xpc_object_t plist = zqbb_read_dictionary(path);
    if (!plist) return false;
    xpc_object_t dictionary = section ? xpc_dictionary_get_value(plist, section) : plist;
    xpc_object_t value = dictionary && xpc_get_type(dictionary) == XPC_TYPE_DICTIONARY ?
                         xpc_dictionary_get_value(dictionary, name) : NULL;
    bool enabled = false;
    if (value) {
        xpc_type_t type = xpc_get_type(value);
        if (type == XPC_TYPE_BOOL) enabled = xpc_bool_get_value(value);
        else if (type == XPC_TYPE_INT64) enabled = xpc_int64_get_value(value) != 0;
        else if (type == XPC_TYPE_UINT64) enabled = xpc_uint64_get_value(value) != 0;
        else if (type == XPC_TYPE_DOUBLE) enabled = xpc_double_get_value(value) != 0;
        else if (type == XPC_TYPE_STRING) {
            enabled = zqbb_configuration_string_bool(xpc_string_get_string_ptr(value));
        }
    }
    xpc_release(plist);
    return enabled;
}
