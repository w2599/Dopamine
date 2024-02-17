#include <xpc/xpc.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdbool.h>

extern xpc_object_t xpc_create_from_plist(const void* buf, size_t len);
bool wantInject(const char *execName, const char *jectPath) {
    struct stat s = {};
    int fd = open(jectPath, O_RDONLY);
    if (fd < 0) return 0;

    if (fstat(fd, &s) != 0) {
		close(fd);
		return 0;
    }

    void *addr = mmap(NULL, s.st_size, PROT_READ, MAP_FILE | MAP_PRIVATE, fd, 0);
    close(fd);
    if (addr == MAP_FAILED) return 0;

    xpc_object_t xplist = xpc_create_from_plist(addr, s.st_size);
    munmap(addr, s.st_size);
    if (!xplist) return 0;

    bool result = xpc_get_type(xplist) == XPC_TYPE_DICTIONARY && xpc_dictionary_get_bool(xplist, execName);
    xpc_release(xplist);
    
    return result;
}