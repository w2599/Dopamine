#include "trustcache_fs.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <errno.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include "signatures.h"
#include "trustcache.h"

// 普通资源无需签名，但带 Mach-O 标记的损坏文件必须返回错误。
static int file_has_macho_magic(const char *path)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    uint32_t magic = 0;
    ssize_t size = 0;
    while (size < sizeof(magic)) {
        ssize_t n = read(fd, (char *)&magic + size, sizeof(magic) - size);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { size = -1; break; }
        if (n == 0) break;
        size += n;
    }
    close(fd);
    if (size < 0) return -1;
    if (size != sizeof(magic)) return 0;
    return magic == MH_MAGIC || magic == MH_CIGAM || magic == MH_MAGIC_64 || magic == MH_CIGAM_64 ||
        magic == FAT_MAGIC || magic == FAT_CIGAM || magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64;
}

// 遍历目录并逐层传播读取、解析和回调错误。
static int walk_machos_in_dir(const char *path, int (^visit)(const char *, Fat *), bool recursive)
{
    DIR *dir = opendir(path);
    if (!dir) return -1;
    int result = 0;
    struct dirent *entry;
    for (;;) {
        errno = 0;
        entry = readdir(dir);
        if (!entry) { if (errno) result = -1; break; }
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        char *full = NULL;
        if (asprintf(&full, "%s/%s", path, entry->d_name) < 0) { result = -1; break; }
        struct stat st;
        if (lstat(full, &st) != 0) result = -1;
        else if (S_ISDIR(st.st_mode) && recursive) result = walk_machos_in_dir(full, visit, true);
        else if (S_ISREG(st.st_mode)) {
            int isMacho = file_has_macho_magic(full);
            if (isMacho < 0) result = -1;
            else if (isMacho) {
                Fat *fat = fat_init_from_path(full);
                if (!fat) result = -1;
                else { result = visit(full, fat); fat_free(fat); }
            }
        }
        free(full);
        if (result != 0) break;
    }
    closedir(dir);
    return result;
}

// 任一文件失败时丢弃目录的部分结果，禁止误报全部信任成功。
static int directory_collect_untrusted_cdhashes_by_path(const char *path, bool recursive, cdhash_t **out, uint32_t *countOut)
{
    *out = NULL;
    *countOut = 0;
    __block cdhash_t *hashes = NULL;
    __block uint32_t count = 0;
    int result = walk_machos_in_dir(path, ^int(const char *file, Fat *fat) {
        cdhash_t *next = NULL;
        uint32_t nextCount = 0;
        int r = fat_collect_untrusted_cdhashes(fat, &next, &nextCount);
        if (r != 0) { free(next); return r; }
        if (nextCount > UINT32_MAX - count) { free(next); return -1; }
        if (nextCount) {
            cdhash_t *expanded = realloc(hashes, ((size_t)count + nextCount) * sizeof(cdhash_t));
            if (!expanded) { free(next); return -1; }
            hashes = expanded;
            memcpy(&hashes[count], next, (size_t)nextCount * sizeof(cdhash_t));
            count += nextCount;
        }
        free(next);
        return 0;
    }, recursive);
    if (result != 0) { free(hashes); return result; }
    *out = hashes;
    *countOut = count;
    return 0;
}

// 收集单个文件的散列，并返回收集或缓存追加错误。
int jb_trustcache_add_file(const char *path)
{
    cdhash_t *hashes = NULL;
    uint32_t count = 0;
    int result = file_collect_untrusted_cdhashes_by_path(path, &hashes, &count);
    if (result == 0 && count > 0) result = jb_trustcache_add_cdhashes(hashes, count);
    free(hashes);
    return result;
}

// 收集目录中的全部散列，收集完整后才追加缓存。
int jb_trustcache_add_directory(const char *path, bool recursive)
{
    cdhash_t *hashes = NULL;
    uint32_t count = 0;
    int result = directory_collect_untrusted_cdhashes_by_path(path, recursive, &hashes, &count);
    if (result == 0 && count > 0) result = jb_trustcache_add_cdhashes(hashes, count);
    free(hashes);
    return result;
}
