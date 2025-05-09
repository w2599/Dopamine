#include <xpc/xpc.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>

typedef struct {
    time_t mtime;
    off_t size;
    xpc_object_t cached_plist;
} CacheEntry;

static CacheEntry whitelist_cache = { 0, 0, NULL };

extern xpc_object_t xpc_create_from_plist(const void* buf, size_t len);

bool isWhiteList(const char *path, const char *injectSystemPath) {
    if (!path || !injectSystemPath)
        return 0;

    if (access(injectSystemPath, F_OK) != 0)
        return 0;

    struct stat s = {};
    if (stat(injectSystemPath, &s) != 0)
        return 0;

    // Check if we need to reload the cache
    if (whitelist_cache.cached_plist == NULL || 
        whitelist_cache.mtime != s.st_mtime || 
        whitelist_cache.size != s.st_size) {
        
        // Release old cache
        if (whitelist_cache.cached_plist) {
            xpc_release(whitelist_cache.cached_plist);
            whitelist_cache.cached_plist = NULL;
        }

        int fd = open(injectSystemPath, O_RDONLY);
        if (fd < 0) return 0;

        void *addr = mmap(NULL, s.st_size, PROT_READ, MAP_FILE | MAP_PRIVATE, fd, 0);
        close(fd);
        if (addr == MAP_FAILED) return 0;

        xpc_object_t xplist = xpc_create_from_plist(addr, s.st_size);
        munmap(addr, s.st_size);
        if (!xplist || xpc_get_type(xplist) != XPC_TYPE_DICTIONARY) {
            if (xplist) xpc_release(xplist);
            return 0;
        }

        // Update cache
        whitelist_cache.cached_plist = xplist;
        whitelist_cache.mtime = s.st_mtime;
        whitelist_cache.size = s.st_size;
    }

    __block bool found = 0;
    xpc_dictionary_apply(whitelist_cache.cached_plist, ^bool(const char *key, xpc_object_t value) {
        if (xpc_get_type(value) == XPC_TYPE_BOOL && xpc_bool_get_value(value)) {
            if (strstr(path, key)) {
                found = 1;
                return false; // stop iteration
            }
        }
        return true; // continue
    });

    return found;
}