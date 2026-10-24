#import <Foundation/Foundation.h>
// 两种启动路径共用签名租约，提前准备包内库并持有到子进程退出。
#include "trollstore_lite_txm.h"
#include "trollstore_lite_macho.h"
#include "trollstore_lite_bundle.h"
#include <libjailbreak/txm_trust.h>
#include <libjailbreak/kernel.h>
#include <libjailbreak/util.h>
#include <libroothider/common.h>
#include <libroothider/unsandbox.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

extern int posix_spawnattr_getarchpref_np(const posix_spawnattr_t *, size_t,
                                         cpu_type_t *, cpu_subtype_t *, size_t *);

// 读取经过有界校验的 XML entitlement。
static NSDictionary *image_entitlements(const struct trollstore_lite_macho *image)
{
    if (!image->entitlementSize) return nil;
    NSMutableData *data = [NSMutableData dataWithLength:image->entitlementSize];
    if (!data || trollstore_lite_macho_read(image, image->entitlementOffset, data.mutableBytes, data.length)) return nil;
    id value = [NSPropertyListSerialization propertyListWithData:data options:NSPropertyListImmutable format:NULL error:nil];
    return [value isKindOfClass:NSDictionary.class] ? value : nil;
}

// 将十六进制字符转换为身份字节。
static int hex_digit(char value)
{
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

// 按 TrollStoreLite 的 116 字节身份格式解析保留列表，禁止静默丢弃内存失败。
static int copy_preserved(NSDictionary *entitlements, struct txm_trust_identity **out, size_t *count)
{
    *out = NULL; *count = 0;
    id values = entitlements[@"jb.pmap_cs.preserve_trust"];
    if (![values isKindOfClass:NSArray.class] || ![values count]) return 0;
    if ([values count] > 1024) return E2BIG;
    struct txm_trust_identity *identities = calloc([values count], sizeof(*identities));
    if (!identities) return ENOMEM;
    for (id value in values) {
        if (![value isKindOfClass:NSString.class]) continue;
        const char *encoded = [value UTF8String];
        if (!encoded || strlen(encoded) != sizeof(*identities) * 2) continue;
        struct txm_trust_identity identity = {0};
        bool valid = true;
        for (size_t i = 0; i < sizeof(identity); i++) {
            int high = hex_digit(encoded[i * 2]), low = hex_digit(encoded[i * 2 + 1]);
            if (high < 0 || low < 0) { valid = false; break; }
            ((uint8_t *)&identity)[i] = (high << 4) | low;
        }
        if (!valid || identity.version != 1 || !identity.hashSize || identity.hashSize > 48
            || !identity.anchorCount || identity.anchorCount > 2) continue;
        identities[(*count)++] = identity;
    }
    *out = identities;
    return 0;
}

// 固定实际打开的 vnode，并令内核建立该切片对应的 TXM 签名对象。
static int attach_image(const struct trollstore_lite_macho *image, uint64_t *vnode, uint64_t *address)
{
    *vnode = proc_fd_vnode(proc_self(), image->fd);
    if (!*vnode) return EFAULT;
    if (fcntl(image->fd, F_ADDFILESIGS, &image->signature)) return errno ?: EIO;
    return txm_vnode_trust_address(*vnode, image->signature.fs_file_start, address);
}

// 查找当前启动文件所属的最近应用包，扩展不能扫描其他扩展的私有代码。
static NSURL *owning_bundle(const char *path)
{
    NSString *name = [[NSString stringWithUTF8String:path] stringByResolvingSymlinksInPath];
    for (NSString *cursor = name.stringByDeletingLastPathComponent; cursor.length > 1; cursor = cursor.stringByDeletingLastPathComponent) {
        NSString *ext = cursor.pathExtension;
        if ([ext isEqualToString:@"app"] || [ext isEqualToString:@"appex"])
            return [NSURL fileURLWithPath:cursor isDirectory:YES];
    }
    return nil;
}

// 仅为同团队、未保留的库取得共享租约，不跟随符号链接或进入其他应用/扩展包。
static int prepare_libraries(const char *path, const struct trollstore_lite_macho *mainImage,
    const struct txm_signing_scope *scope, const struct txm_trust_identity *preserved,
    size_t preservedCount, struct trollstore_lite_txm_session *session)
{
    NSURL *bundle = owning_bundle(path);
    if (!bundle) return EINVAL;
    cpu_type_t types[3] = {CPU_TYPE_ARM64, CPU_TYPE_ARM64, CPU_TYPE_ARM64};
    cpu_subtype_t subtypes[3];
    size_t architectureCount = 0;
    cpu_subtype_t subtype = mainImage->header.cpusubtype & ~CPU_SUBTYPE_MASK;
    // arm64e/arm64v8 可加载普通 arm64 库，普通 arm64 进程不能选择 arm64e 切片。
    if (subtype == CPU_SUBTYPE_ARM64E) subtypes[architectureCount++] = CPU_SUBTYPE_ARM64E;
    if (subtype == CPU_SUBTYPE_ARM64E || subtype == CPU_SUBTYPE_ARM64_V8)
        subtypes[architectureCount++] = CPU_SUBTYPE_ARM64_V8;
    subtypes[architectureCount++] = CPU_SUBTYPE_ARM64_ALL;
    // 块捕获架构指针，调用期间数组始终由当前栈持有。
    const cpu_type_t *preferredTypes = types;
    const cpu_subtype_t *preferredSubtypes = subtypes;
    return trollstore_lite_bundle_enumerate(bundle.fileSystemRepresentation, true, ^int(const char *imagePath) {
        int fd = open(imagePath, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0) return errno ?: EIO;
        struct trollstore_lite_macho image;
        int result = trollstore_lite_macho_find(fd, preferredTypes, preferredSubtypes, architectureCount, &image);
        if (result || (image.header.filetype != MH_DYLIB && image.header.filetype != MH_BUNDLE)) { close(fd); return 0; }
        uint64_t vnode = 0, address = 0;
        bool eligible = false;
        result = attach_image(&image, &vnode, &address);
        if (!result) result = txm_trust_library_eligible(address, scope, preserved, preservedCount, &eligible);
        if (result || !eligible) {
            close(fd);
            return result;
        }
        if (session->count >= TROLLSTORE_LITE_TXM_MAX_IMAGES) { close(fd); return E2BIG; }
        result = trollstore_lite_txm_acquire(fd, vnode, address, &session->images[session->count]);
        if (result) return result;
        session->count++;
        return 0;
    });
}

// 仅接受显式请求自定义信任的 TrollStoreLite，两种启动路径失败时均回滚整组。
int trollstore_lite_txm_begin(const char *path, const posix_spawnattr_t *attributes,
                        struct trollstore_lite_txm_session **out)
{
    *out = NULL;
    if (!path || !hasTrollstoreLiteMarker(path) || !txm_local_signing_supported()) return 0;
    @autoreleasepool {
        cpu_type_t types[4] = {0}; cpu_subtype_t subtypes[4] = {0}; size_t count = 0;
        int status = posix_spawnattr_getarchpref_np(attributes, 4, types, subtypes, &count);
        if (status || count > 4) return status ?: EINVAL;
        int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0) return 0;
        struct trollstore_lite_macho image;
        status = trollstore_lite_macho_find(fd, types, subtypes, count, &image);
        NSDictionary *entitlements = status ? nil : image_entitlements(&image);
        id trust = entitlements[@"jb.pmap_cs.custom_trust"];
        if (status || image.header.filetype != MH_EXECUTE || ![trust isKindOfClass:NSString.class]
            || ![trust isEqualToString:@"PMAP_CS_APP_STORE"]) { close(fd); return 0; }
        short flags = 0;
        status = posix_spawnattr_getflags(attributes, &flags);
        if (status || (flags & POSIX_SPAWN_SETEXEC)) { close(fd); return status ?: ENOTSUP; }
        struct txm_trust_identity *preserved = NULL; size_t preservedCount = 0;
        status = copy_preserved(entitlements, &preserved, &preservedCount);
        uint64_t vnode = 0, address = 0;
        if (!status) status = attach_image(&image, &vnode, &address);
        struct txm_signing_scope scope;
        if (!status) status = txm_trust_copy_scope(address, &scope);
        struct trollstore_lite_txm_session *session = status ? NULL : calloc(1, sizeof(*session));
        if (!status && !session) status = ENOMEM;
        if (!status) {
            status = trollstore_lite_txm_acquire(fd, vnode, address, &session->images[0]);
            fd = -1;
            if (!status) session->count = 1;
        }
        if (!status) status = prepare_libraries(path, &image, &scope, preserved, preservedCount, session);
        free(preserved);
        if (fd >= 0) close(fd);
        if (status) { trollstore_lite_txm_end(session, 0); return status; }
        *out = session;
        return 0;
    }
}
