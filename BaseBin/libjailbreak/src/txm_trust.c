#include "txm_trust.h"
#include "kernel.h"
#include "primitives.h"
#include <errno.h>
#include <string.h>
#include <libkern/OSCacheControl.h>
#include <dispatch/dispatch.h>
#include <sys/utsname.h>
#include <stdio.h>

// 私有布局不进入 gSystemInfo，避免改变其他组件的共享结构 ABI。
static struct {
    uint32_t pmapTrust, csmObject;
} txmLayout;

// 仅在实际需要 TXM 时识别 Relaxin 已验证的版本，不修改全局偏移表。
bool txm_local_signing_supported(void)
{
    if (!ksymbol(SPTMArgs) || !koffsetof(pmap, txm_address_space)) return false;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        struct utsname name;
        if (uname(&name) != 0) return;
        const char *version = strstr(name.version, "xnu-");
        unsigned long long major = 0;
        if (!version || sscanf(version, "xnu-%llu", &major) != 1) return;
        if (major == 10002 || major == 10063) {
            txmLayout.pmapTrust = 0xB8;
            txmLayout.csmObject = major == 10002 ? 0xB8 : 0xC0;
        }
    });
    return txmLayout.csmObject && koffsetof(vnode, un) && koffsetof(ubc_info, cs_blobs)
        && koffsetof(cs_blob, base_offset) && koffsetof(proc, textvp)
        && koffsetof(TXMCodeRegion, codeSignature) && koffsetof(TXMAddressSpace, mainRegion)
        && koffsetof(TXMCodeSignature, codeDirectory) && koffsetof(TXMCodeSignature, trustPair);
}

// TXM 数据始终通过物理别名读取，禁止跨页访问。
static int txm_read(uint64_t address, void *out, size_t size)
{
    if (!vm_real_kernel_page_size || !size || !out || !address
        || size > vm_real_kernel_page_size
        || address % vm_real_kernel_page_size > vm_real_kernel_page_size - size)
        return EINVAL;
    return kaccess_mapped(address, size, ^(void *mapped) {
        memcpy(out, mapped, size);
    }) == 0 ? 0 : EIO;
}

// 校验指针范围，并允许链表末尾使用空指针。
static int txm_read_pointer(uint64_t address, uint64_t *pointer, bool optional)
{
    uint64_t raw = 0;
    int status = txm_read(address, &raw, sizeof(raw));
    if (status) return status;
    *pointer = UNSIGN_PTR(raw);
    uint64_t mask = kconstant(pointer_mask);
    if (!*pointer) return optional ? 0 : EFAULT;
    return mask && (*pointer & mask) == mask ? 0 : EFAULT;
}

// 比较原值后写入完整信任对，刷新缓存并通过独立映射回读。
static int txm_write_pair(uint64_t address, uint16_t expected, uint16_t replacement)
{
    if (!address || (address & 1)) return EINVAL;
    __block int status = EIO;
    int mappedStatus = kaccess_mapped(address, sizeof(expected), ^(void *mapped) {
        volatile uint16_t *value = mapped;
        if (*value != expected) { status = EBUSY; return; }
        if (expected != replacement) {
            *value = replacement;
            sys_dcache_flush(mapped, sizeof(expected));
            __asm__ volatile("dsb sy" ::: "memory");
        }
        status = 0;
    });
    if (mappedStatus != 0) return EIO;
    if (status) return status;
    uint16_t observed = 0;
    status = txm_read(address, &observed, sizeof(observed));
    return status ? status : (observed == replacement ? 0 : EIO);
}

// 从固定 vnode 的指定架构切片找到 TXM 签名，拒绝损坏的链表或签名。
int txm_vnode_trust_address(uint64_t vnode, int64_t sliceOffset, uint64_t *address)
{
    if (!address) return EINVAL;
    *address = 0;
    if (!txm_local_signing_supported()) return ENOTSUP;
    if (!vnode || sliceOffset < 0) return EINVAL;
    uint64_t ubc, blob;
    int status = txm_read_pointer(vnode + koffsetof(vnode, un), &ubc, false);
    if (status) return status;
    status = txm_read_pointer(ubc + koffsetof(ubc_info, cs_blobs), &blob, false);
    if (status) return status;
    for (unsigned i = 0; blob && i < 32; i++) {
        int64_t offset = -1;
        status = txm_read(blob + koffsetof(cs_blob, base_offset), &offset, sizeof(offset));
        if (status) return status;
        if (offset == sliceOffset) {
            uint64_t signature, directory;
            status = txm_read_pointer(blob + txmLayout.csmObject, &signature, false);
            if (status) return status;
            status = txm_read_pointer(signature + koffsetof(TXMCodeSignature, codeDirectory), &directory, false);
            if (status) return status;
            uint32_t magic = 0;
            status = txm_read(directory, &magic, sizeof(magic));
            if (status) return status;
            if (__builtin_bswap32(magic) != 0xfade0c02) return ENOEXEC;
            *address = signature + koffsetof(TXMCodeSignature, trustPair);
            return 0;
        }
        status = txm_read_pointer(blob + koffsetof(cs_blob, next), &blob, true);
        if (status) return status;
    }
    return blob ? ELOOP : ENOENT;
}

// 保存原值再临时调整信任；失败时保留状态，供调用方回滚。
int txm_trust_prepare(uint64_t address, struct txm_trust_state *state)
{
    if (!state) return EINVAL;
    *state = (struct txm_trust_state){0};
    if (!txm_local_signing_supported()) return ENOTSUP;
    if (!address || (address & 1)) return EINVAL;
    uint16_t pair = 0;
    int status = txm_read(address, &pair, sizeof(pair));
    if (status) return status;
    if (!pair) return EACCES;
    if ((pair & 0xff) != (pair >> 8)) return EBUSY;
    state->address = address;
    state->original = pair;
    return txm_write_pair(address, pair, 0x0505);
}

// 允许幂等恢复；遇到第三方修改时拒绝覆盖。
int txm_trust_restore(const struct txm_trust_state *state)
{
    if (!state || !state->address || !state->original) return EINVAL;
    uint16_t pair = 0;
    int status = txm_read(state->address, &pair, sizeof(pair));
    if (status) return status;
    if (pair == state->original) return 0;
    return txm_write_pair(state->address, 0x0505, state->original);
}

// 验证子进程确实加载租约对应的文件，并已获得进程级 LOCAL_SIGNING 信任。
int txm_trust_validate_process(uint64_t proc, uint64_t vnode, uint64_t address)
{
    if (!txm_local_signing_supported()) return ENOTSUP;
    if (!proc || !vnode || !address) return EINVAL;
    uint64_t text, map, pmap, space, region, signature;
    int status = txm_read_pointer(proc + koffsetof(proc, textvp), &text, false);
    if (status) return status;
    if (text != vnode) return ESTALE;
    uint64_t task = proc_task(proc);
    if (!task) return EFAULT;
    status = txm_read_pointer(task + koffsetof(task, map), &map, false);
    if (status) return status;
    status = txm_read_pointer(map + koffsetof(vm_map, pmap), &pmap, false);
    if (status) return status;
    uint8_t trust = 0;
    status = txm_read(pmap + txmLayout.pmapTrust, &trust, sizeof(trust));
    if (status) return status;
    if (trust != TXM_LOCAL_SIGNING_TRUST) return EACCES;
    status = txm_read_pointer(pmap + koffsetof(pmap, txm_address_space), &space, false);
    if (status) return status;
    status = txm_read_pointer(space + koffsetof(TXMAddressSpace, mainRegion), &region, false);
    if (status) return status;
    status = txm_read_pointer(region + koffsetof(TXMCodeRegion, codeSignature), &signature, false);
    if (status) return status;
    return signature + koffsetof(TXMCodeSignature, trustPair) == address ? 0 : EPROTO;
}
