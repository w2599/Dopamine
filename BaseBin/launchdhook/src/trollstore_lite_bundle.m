#import <Foundation/Foundation.h>
#include "trollstore_lite_bundle.h"
#include <errno.h>
#include <fcntl.h>
#include <fts.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <sys/stat.h>
#include <unistd.h>

// 只缓存资源文件的元数据，不缓存信任结果、签名内容或内核地址。
static NSCache<NSString *, NSData *> *resource_cache(void)
{
    static NSCache<NSString *, NSData *> *cache;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        cache = [NSCache new];
        cache.countLimit = 32768;
        cache.totalCostLimit = 16 * 1024 * 1024;
    });
    return cache;
}

// 同时检查 inode、大小和纳秒级修改时间，原地替换或重签后必须重新读取。
static bool same_file(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino && a->st_gen == b->st_gen
        && a->st_mode == b->st_mode && a->st_size == b->st_size
        && a->st_mtimespec.tv_sec == b->st_mtimespec.tv_sec
        && a->st_mtimespec.tv_nsec == b->st_mtimespec.tv_nsec
        && a->st_ctimespec.tv_sec == b->st_ctimespec.tv_sec
        && a->st_ctimespec.tv_nsec == b->st_ctimespec.tv_nsec;
}

// 保留所有 Mach-O/FAT 魔数，实际架构和签名仍由原有解析器校验。
static bool macho_magic(uint32_t magic)
{
    return magic == MH_MAGIC || magic == MH_CIGAM || magic == MH_MAGIC_64 || magic == MH_CIGAM_64
        || magic == FAT_MAGIC || magic == FAT_CIGAM || magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64;
}

// 未变化的资源免于重复打开；只把读取前后身份一致的非 Mach-O 文件加入缓存。
static int is_image(const FTSENT *entry, bool *image)
{
    *image = false;
    NSString *key = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:entry->fts_path
                                                                             length:entry->fts_pathlen];
    if (!key) return EINVAL;
    NSCache *cache = resource_cache();
    NSData *cached = [cache objectForKey:key];
    if (cached.length == sizeof(struct stat)) {
        struct stat previous;
        memcpy(&previous, cached.bytes, sizeof(previous));
        if (same_file(&previous, entry->fts_statp)) return 0;
    }

    int fd = open(entry->fts_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return errno ?: EIO;
    struct stat before, after;
    int status = 0;
    if (fstat(fd, &before)) status = errno ?: EIO;
    else if (!S_ISREG(before.st_mode) || !same_file(&before, entry->fts_statp)) status = ESTALE;
    uint32_t magic = 0;
    ssize_t bytes = -1;
    if (!status) {
        do { bytes = pread(fd, &magic, sizeof(magic), 0); } while (bytes < 0 && errno == EINTR);
        if (bytes < 0) status = errno ?: EIO;
        else *image = bytes == sizeof(magic) && macho_magic(magic);
    }
    if (!status && !*image) {
        if (fstat(fd, &after)) status = errno ?: EIO;
        else if (!same_file(&before, &after)) status = ESTALE;
        else [cache setObject:[NSData dataWithBytes:&after length:sizeof(after)] forKey:key
                         cost:sizeof(after) + key.length * sizeof(unichar)];
    } else {
        [cache removeObjectForKey:key];
    }
    close(fd);
    return status;
}

// 使用物理目录遍历共享资源筛选；每次重新检查元数据，新增文件也不会遗漏。
int trollstore_lite_bundle_enumerate(const char *path, bool skipNestedBundles,
                                    int (^visit)(const char *path))
{
    if (!path || !visit) return EINVAL;
    char root[PATH_MAX];
    if (!realpath(path, root)) return errno ?: EIO;
    char *paths[] = {root, NULL};
    FTS *tree = fts_open(paths, FTS_PHYSICAL | FTS_NOCHDIR, NULL);
    if (!tree) return errno ?: EIO;
    int status = 0;
    size_t visited = 0;
    for (;;) {
        errno = 0;
        FTSENT *entry = fts_read(tree);
        if (!entry) { status = errno; break; }
        if (entry->fts_info == FTS_DP) continue;
        // 保留 TXM 原有的单包扫描上限，整包信任仍覆盖所有嵌套扩展。
        if (skipNestedBundles && ++visited > 100000) { status = E2BIG; break; }
        if (entry->fts_info == FTS_D) {
            const char *ext = strrchr(entry->fts_name, '.');
            if (skipNestedBundles && entry->fts_level > 0 && ext
                && (!strcmp(ext, ".app") || !strcmp(ext, ".appex"))) {
                if (fts_set(tree, entry, FTS_SKIP)) { status = errno ?: EIO; break; }
            }
        } else if (entry->fts_info == FTS_ERR || entry->fts_info == FTS_DNR || entry->fts_info == FTS_NS) {
            status = entry->fts_errno ?: EIO;
            break;
        } else if (entry->fts_info == FTS_F) {
            @autoreleasepool {
                bool image = false;
                status = is_image(entry, &image);
                if (!status && image) status = visit(entry->fts_path);
            }
            if (status) break;
        }
    }
    int closed = fts_close(tree);
    return status ?: (closed ? (errno ?: EIO) : 0);
}
