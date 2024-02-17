#include <xpc/xpc.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdbool.h>

typedef struct {
    off_t fileSize;
    time_t fileMtime;
    xpc_object_t xplist;
} CacheEntry;

static CacheEntry cache = { 0, 0, NULL };

extern xpc_object_t xpc_create_from_plist(const void* buf, size_t len);

bool wantInject(const char *execName, const char *injectPath) {
    struct stat s = {};
    if (stat(injectPath, &s) != 0 || s.st_size <= 0) {
        return false;
    }

    if (cache.fileSize == s.st_size && cache.fileMtime == s.st_mtime) {
        return xpc_get_type(cache.xplist) == XPC_TYPE_DICTIONARY && xpc_dictionary_get_bool(cache.xplist, execName);
    }

    int fd = open(injectPath, O_RDONLY);
    if (fd < 0) return false;

    void *addr = mmap(NULL, s.st_size, PROT_READ, MAP_FILE | MAP_PRIVATE, fd, 0);
    close(fd);
    if (addr == MAP_FAILED) return false;

    xpc_object_t xplist = xpc_create_from_plist(addr, s.st_size);
    munmap(addr, s.st_size);
    if (!xplist) return false;

    if (cache.xplist) xpc_release(cache.xplist);
    cache.fileSize = s.st_size;
    cache.fileMtime = s.st_mtime;
    cache.xplist = xplist;

    return xpc_get_type(xplist) == XPC_TYPE_DICTIONARY && xpc_dictionary_get_bool(xplist, execName);
}