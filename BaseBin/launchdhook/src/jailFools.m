#import <Foundation/Foundation.h>

#include <libroothider/libroothider.h>

#include <fts.h>


int roothide_launchd_trust_executable(const char *path);
// 信任框架目录中带有 JailFools 旁路标记的文件。
static void scanJailFools(const char *frameworksPath) {
    char *paths[] = {(char *)frameworksPath, NULL};

    // 使用 FTS 递归遍历 Frameworks 下所有文件
    FTS *fts = fts_open(paths, FTS_NOCHDIR | FTS_PHYSICAL, NULL);
    if (!fts)
        return;
    FTSENT *ent;
    while ((ent = fts_read(fts)) != NULL) {
        // 只处理普通文件
        if (ent->fts_info != FTS_F)
            continue;
        // 判断是否为 .jailFools 标记文件
        size_t suffixLength = strlen(".jailFools");
        size_t len = ent->fts_namelen;
        if (len <= suffixLength || memcmp(ent->fts_name + len - suffixLength, ".jailFools", suffixLength) != 0)
            continue;
        // 去掉 .jailFools 后缀，得到 Mach-O 路径
        size_t newLen = ent->fts_pathlen - suffixLength;
        char newPath[PATH_MAX];
        if (newLen >= sizeof(newPath)) continue;
        memcpy(newPath, ent->fts_path, newLen);
        newPath[newLen] = '\0';
        // 添加到 trustcache
        roothide_launchd_trust_executable(newPath);
    }
    fts_close(fts);
}

// 在启动应用前准备 JailFools 框架的信任缓存。
int trust_jailfools_bundle_before_spawn(const char *path) {
    if (!hasJailFoolsMarker(path))
        return 0;

    NSString *bundlePath = getAppBundlePathFromSpawnPath(path);
    if (!bundlePath)
        return EINVAL;

    NSString *frameworksPath = [bundlePath stringByAppendingPathComponent:@"Frameworks"];
    scanJailFools(frameworksPath.fileSystemRepresentation);

    return 0;
}
