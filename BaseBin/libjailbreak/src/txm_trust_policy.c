// 复用 Relaxin 的签名团队范围及 preserve_trust 身份规则，供 TrollStoreLite 启动前信任使用。
#include "txm_trust.h"
#include "primitives.h"
#include "info.h"
#include <errno.h>
#include <string.h>
#include <choma/CodeDirectory.h>

// 每次最多读取 64 字节且不跨页，所有 TXM 数据均经物理别名读取。
static int policy_read(uint64_t address, void *out, size_t size)
{
    size_t page = vm_real_kernel_page_size;
    if (!address || !out || !page || (page & (page - 1)) || size > UINT64_MAX - address) return EINVAL;
    for (size_t done = 0; done < size;) {
        size_t chunk = size - done, remaining = page - ((address + done) & (page - 1));
        if (chunk > 64) chunk = 64;
        if (chunk > remaining) chunk = remaining;
        if (kaccess_mapped(address + done, chunk, ^(void *mapped) {
            memcpy((char *)out + done, mapped, chunk);
        }) != 0) return EIO;
        done += chunk;
    }
    return 0;
}

// 从已校验的信任对地址取得 CodeDirectory，拒绝未知布局与损坏长度。
static int policy_directory(uint64_t address, uint64_t *directory, CS_CodeDirectory *header)
{
    if (!txm_local_signing_supported() || address < koffsetof(TXMCodeSignature, trustPair)) return ENOTSUP;
    uint64_t raw = 0;
    int status = policy_read(address - koffsetof(TXMCodeSignature, trustPair)
        + koffsetof(TXMCodeSignature, codeDirectory), &raw, sizeof(raw));
    if (status) return status;
    *directory = UNSIGN_PTR(raw);
    uint64_t mask = kconstant(pointer_mask);
    if (!*directory || !mask || (*directory & mask) != mask) return EFAULT;
    status = policy_read(*directory, header, sizeof(*header));
    if (status) return status;
    uint32_t size = __builtin_bswap32(header->length);
    return __builtin_bswap32(header->magic) == CSMAGIC_CODEDIRECTORY
        && size >= sizeof(*header) && size <= 16 * 1024 * 1024 ? 0 : ENOEXEC;
}

// 有界读取 Team ID 或 identifier，不允许空字符串或越过 CodeDirectory。
static int policy_string(uint64_t address, bool team, char out[256])
{
    uint64_t directory; CS_CodeDirectory header;
    int status = policy_directory(address, &directory, &header);
    if (status) return status;
    if (team && __builtin_bswap32(header.version) < 0x20200) return ENOENT;
    uint32_t offset = __builtin_bswap32(team ? header.teamOffset : header.identOffset);
    uint32_t length = __builtin_bswap32(header.length);
    if (!offset) return ENOENT;
    if (offset < sizeof(header) || offset >= length || directory > UINT64_MAX - offset) return ENOEXEC;
    size_t available = length - offset;
    if (available > 256) available = 256;
    memset(out, 0, 256);
    for (size_t done = 0; done < available;) {
        size_t chunk = available - done;
        if (chunk > 64) chunk = 64;
        status = policy_read(directory + offset + done, out + done, chunk);
        if (status) return status;
        if (memchr(out + done, 0, chunk)) return out[0] ? 0 : ENAMETOOLONG;
        done += chunk;
    }
    return ENAMETOOLONG;
}

// 优先采用包内共享 Team ID，兼容缺少 Team ID 的旧签名。
int txm_trust_copy_scope(uint64_t address, struct txm_signing_scope *scope)
{
    if (!scope) return EINVAL;
    *scope = (struct txm_signing_scope){.team = true};
    int status = policy_string(address, true, scope->value);
    if (status != ENOENT) return status;
    scope->team = false;
    return policy_string(address, false, scope->value);
}

// 按签名声明的哈希类型校验固定长度，保持与 TrollStoreLite 编码一致。
static bool hash_shape(uint8_t type, uint8_t size)
{
    return ((type == 1 || type == 3) && size == 20) || (type == 2 && size == 32) || (type == 4 && size == 48);
}

// 读取身份锚点；边界由上层验证过的完整哈希表保证。
static int policy_hash(uint64_t directory, uint32_t hashOffset, uint8_t size, int32_t slot, uint8_t out[48])
{
    int64_t offset = (int64_t)hashOffset + (int64_t)slot * size;
    if (offset < 0 || directory > UINT64_MAX - (uint64_t)offset) return ENOEXEC;
    return policy_read(directory + offset, out, size);
}

// 使用第 1 页与最后一页哈希，单页文件则采用首个非空特殊槽。
static int policy_identity(uint64_t address, struct txm_trust_identity *identity)
{
    uint64_t directory; CS_CodeDirectory header;
    int status = policy_directory(address, &directory, &header);
    if (status) return status;
    uint32_t length = __builtin_bswap32(header.length), hashOffset = __builtin_bswap32(header.hashOffset);
    uint32_t special = __builtin_bswap32(header.nSpecialSlots), slots = __builtin_bswap32(header.nCodeSlots);
    uint8_t size = header.hashSize;
    if (!hash_shape(header.hashType, size) || hashOffset > length || special > hashOffset / size
        || !slots || slots > INT32_MAX || slots > (length - hashOffset) / size) return ENOEXEC;
    *identity = (struct txm_trust_identity){.version = 1, .hashType = header.hashType, .hashSize = size,
        .codeLimit = header.codeLimit, .codeSlotCount = header.nCodeSlots};
    if (slots > 1) {
        identity->anchorCount = slots > 2 ? 2 : 1;
        identity->anchorSlots[0] = __builtin_bswap32(1);
        status = policy_hash(directory, hashOffset, size, 1, identity->anchorHashes[0]);
        if (status || slots == 2) return status;
        identity->anchorSlots[1] = __builtin_bswap32(slots - 1);
        return policy_hash(directory, hashOffset, size, (int32_t)slots - 1, identity->anchorHashes[1]);
    }
    for (uint32_t i = 1; i <= special; i++) {
        uint8_t hash[48] = {0};
        status = policy_hash(directory, hashOffset, size, -(int32_t)i, hash);
        if (status) return status;
        bool nonzero = false;
        for (uint8_t n = 0; n < size; n++) nonzero |= hash[n] != 0;
        if (!nonzero) continue;
        identity->anchorCount = 1;
        identity->anchorSlots[0] = __builtin_bswap32((uint32_t)-(int32_t)i);
        memcpy(identity->anchorHashes[0], hash, size);
        return 0;
    }
    return ENOENT;
}

// 只降低同签名范围且未被明确保留的库；不提高已有低等级，不改系统或其他团队代码。
int txm_trust_library_eligible(uint64_t address, const struct txm_signing_scope *scope,
    const struct txm_trust_identity *preserved, size_t count, bool *eligible)
{
    if (!scope || !eligible || (count && !preserved)) return EINVAL;
    *eligible = false;
    char value[256];
    int status = policy_string(address, scope->team, value);
    if (status == ENOENT) return 0;
    if (status) return status;
    if (strcmp(value, scope->value)) return 0;
    uint16_t pair = 0;
    status = policy_read(address, &pair, sizeof(pair));
    if (status) return status;
    if ((pair & 255) != (pair >> 8)) return EBUSY;
    // 已是 5 的签名也要加入租约，避免另一进程退出时提前恢复。
    if ((pair & 255) < TXM_LOCAL_SIGNING_TRUST) return 0;
    if (count) {
        struct txm_trust_identity identity;
        status = policy_identity(address, &identity);
        if (status && status != ENOENT) return status;
        if (!status) for (size_t i = 0; i < count; i++)
            if (!memcmp(&identity, &preserved[i], sizeof(identity))) return 0;
    }
    *eligible = true;
    return 0;
}
