// PID 1 只读取有界头部与签名索引，不解析节表，也不按文件提供的大小在栈上分配。
#include "trollstore_lite_macho.h"
#include <mach-o/fat.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#define MAX_SLICES 16
#define ARM64E_ABI_V2 0x80000000U

// 检查文件偏移与切片边界，并处理短读及 EINTR。
int trollstore_lite_macho_read(const struct trollstore_lite_macho *image, uint64_t offset, void *out, size_t size)
{
    if (offset > image->size || size > image->size - offset
        || image->offset > INT64_MAX - offset || size > INT64_MAX - image->offset - offset) return ENOEXEC;
    size_t done = 0;
    while (done < size) {
        ssize_t n = pread(image->fd, (char *)out + done, size - done, image->offset + offset + done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return n < 0 ? errno : ENOEXEC;
        done += n;
    }
    return 0;
}

// 仅提取签名命令，校验全部 SuperBlob 索引后才允许使用 entitlement。
static int read_signature(struct trollstore_lite_macho *image)
{
    uint32_t ncmds = image->header.ncmds, bytes = image->header.sizeofcmds;
    if (bytes > 1024 * 1024 || bytes > image->size - sizeof(image->header)
        || ncmds > 8192 || ncmds > bytes / sizeof(struct load_command)) return ENOEXEC;
    uint64_t cursor = sizeof(image->header), end = cursor + bytes;
    bool found = false;
    for (uint32_t i = 0; i < ncmds; i++) {
        struct load_command command;
        if (cursor > end || end - cursor < sizeof(command)
            || trollstore_lite_macho_read(image, cursor, &command, sizeof(command))) return ENOEXEC;
        if (command.cmdsize < sizeof(command) || command.cmdsize > end - cursor || (command.cmdsize & 7)) return ENOEXEC;
        if (command.cmd == LC_CODE_SIGNATURE) {
            struct linkedit_data_command cs;
            if (found || command.cmdsize != sizeof(cs)
                || trollstore_lite_macho_read(image, cursor, &cs, sizeof(cs))) return ENOEXEC;
            if (cs.dataoff < end || cs.datasize < 12 || cs.datasize > 16 * 1024 * 1024
                || cs.dataoff > image->size || cs.datasize > image->size - cs.dataoff) return ENOEXEC;
            image->signature = (fsignatures_t){image->offset, (void *)(uintptr_t)cs.dataoff, cs.datasize};
            found = true;
        }
        cursor += command.cmdsize;
    }
    if (!found || cursor != end) return ENOEXEC;
    uint64_t start = (uintptr_t)image->signature.fs_blob_start;
    uint32_t header[3];
    if (trollstore_lite_macho_read(image, start, header, sizeof(header))) return ENOEXEC;
    uint32_t magic = __builtin_bswap32(header[0]), length = __builtin_bswap32(header[1]), count = __builtin_bswap32(header[2]);
    if ((magic != 0xfade0cc0 && magic != 0xfade0cc1) || length < 12
        || length > image->signature.fs_blob_size || count > 1024 || count > (length - 12) / 8) return ENOEXEC;
    for (uint32_t i = 0; i < count; i++) {
        uint32_t index[2], blob[2];
        if (trollstore_lite_macho_read(image, start + 12 + (uint64_t)i * 8, index, sizeof(index))) return ENOEXEC;
        uint32_t offset = __builtin_bswap32(index[1]);
        if (offset < 12 + count * 8 || offset > length - 8
            || trollstore_lite_macho_read(image, start + offset, blob, sizeof(blob))) return ENOEXEC;
        uint32_t size = __builtin_bswap32(blob[1]);
        if (size < 8 || size > length - offset) return ENOEXEC;
        if (__builtin_bswap32(index[0]) == 5) {
            if (image->entitlementOffset || __builtin_bswap32(blob[0]) != 0xfade7171
                || size <= 8 || size - 8 > 1024 * 1024) return ENOEXEC;
            image->entitlementOffset = start + offset + 8;
            image->entitlementSize = size - 8;
        }
    }
    return 0;
}

// 按 Relaxin 的 arm64e ABI、arm64v8、arm64 优先级选择切片。
static int select_slice(struct trollstore_lite_macho *slices, size_t count, cpu_type_t type, cpu_subtype_t subtype)
{
    cpu_type_t hostType = 0; cpu_subtype_t hostSubtype = 0;
    size_t typeSize = sizeof(hostType), subtypeSize = sizeof(hostSubtype);
    if (sysctlbyname("hw.cputype", &hostType, &typeSize, NULL, 0)
        || sysctlbyname("hw.cpusubtype", &hostSubtype, &subtypeSize, NULL, 0)) return -1;
    cpu_type_t mask = count == 1 && slices[0].offset == 0 ? CPU_ARCH_MASK : 0;
    if (hostType != CPU_TYPE_ARM64 || (type != CPU_TYPE_ANY && (type & ~mask) != (hostType & ~mask))) return -1;
    subtype &= ~CPU_SUBTYPE_MASK;
    bool any = subtype == (CPU_SUBTYPE_ANY & ~CPU_SUBTYPE_MASK);
    uint32_t choices[] = {CPU_SUBTYPE_ARM64E | ARM64E_ABI_V2, CPU_SUBTYPE_ARM64E, CPU_SUBTYPE_ARM64_V8, CPU_SUBTYPE_ARM64_ALL};
    for (size_t c = 0; c < 4; c++) {
        if (c < 2 && ((hostSubtype & ~CPU_SUBTYPE_MASK) != CPU_SUBTYPE_ARM64E || (!any && subtype != CPU_SUBTYPE_ARM64E))) continue;
        if (c >= 2 && !any && subtype != choices[c]) continue;
        for (size_t i = 0; i < count; i++) {
            if (slices[i].header.cputype != hostType || (uint32_t)slices[i].header.cpusubtype != choices[c]) continue;
            if (c == 1 && slices[i].header.filetype == MH_EXECUTE) continue;
            return (int)i;
        }
    }
    return -1;
}

// 校验 FAT 描述符与实际头部一致；不读取架构无关的节内容。
int trollstore_lite_macho_find(int fd, const cpu_type_t *types, const cpu_subtype_t *subtypes,
                        size_t preferences, struct trollstore_lite_macho *image)
{
    *image = (struct trollstore_lite_macho){0};
    struct stat st;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size < sizeof(struct mach_header_64)) return ENOEXEC;
    struct trollstore_lite_macho file = {.fd = fd, .size = st.st_size}, slices[MAX_SLICES] = {0};
    uint32_t header[2];
    if (trollstore_lite_macho_read(&file, 0, header, sizeof(header))) return ENOEXEC;
    size_t count = 1;
    if (header[0] == MH_MAGIC_64) slices[0] = file;
    else {
        bool wide = header[0] == FAT_CIGAM_64 || header[0] == FAT_MAGIC_64;
        bool swap = header[0] == FAT_CIGAM || header[0] == FAT_CIGAM_64;
        if (!wide && header[0] != FAT_MAGIC && header[0] != FAT_CIGAM) return ENOEXEC;
        count = swap ? __builtin_bswap32(header[1]) : header[1];
        if (!count || count > MAX_SLICES) return ENOEXEC;
        size_t entrySize = wide ? sizeof(struct fat_arch_64) : sizeof(struct fat_arch);
        uint64_t tableEnd = sizeof(struct fat_header) + count * entrySize;
        for (size_t i = 0; i < count; i++) {
            cpu_type_t type; cpu_subtype_t subtype; uint64_t offset, size;
            if (wide) {
                struct fat_arch_64 arch;
                if (trollstore_lite_macho_read(&file, 8 + i * entrySize, &arch, sizeof(arch))) return ENOEXEC;
                type = swap ? __builtin_bswap32(arch.cputype) : arch.cputype;
                subtype = swap ? __builtin_bswap32(arch.cpusubtype) : arch.cpusubtype;
                offset = swap ? __builtin_bswap64(arch.offset) : arch.offset;
                size = swap ? __builtin_bswap64(arch.size) : arch.size;
            } else {
                struct fat_arch arch;
                if (trollstore_lite_macho_read(&file, 8 + i * entrySize, &arch, sizeof(arch))) return ENOEXEC;
                type = swap ? __builtin_bswap32(arch.cputype) : arch.cputype;
                subtype = swap ? __builtin_bswap32(arch.cpusubtype) : arch.cpusubtype;
                offset = swap ? __builtin_bswap32(arch.offset) : arch.offset;
                size = swap ? __builtin_bswap32(arch.size) : arch.size;
            }
            if (offset < tableEnd || offset > file.size || size < sizeof(struct mach_header_64) || size > file.size - offset) return ENOEXEC;
            slices[i] = (struct trollstore_lite_macho){.fd = fd, .offset = offset, .size = size};
            // 不兼容的架构只验证范围，选择阶段会跳过。
            slices[i].header.cputype = type; slices[i].header.cpusubtype = subtype;
        }
    }
    for (size_t i = 0; i < count; i++) {
        if (slices[i].offset && slices[i].header.cputype != CPU_TYPE_ARM64) continue;
        struct mach_header_64 actual;
        if (trollstore_lite_macho_read(&slices[i], 0, &actual, sizeof(actual)) || actual.magic != MH_MAGIC_64) return ENOEXEC;
        if (slices[i].offset && (actual.cputype != slices[i].header.cputype || actual.cpusubtype != slices[i].header.cpusubtype)) return ENOEXEC;
        slices[i].header = actual;
    }
    int selected = -1;
    if (!preferences || !types[0]) selected = select_slice(slices, count, CPU_TYPE_ANY, CPU_SUBTYPE_ANY);
    else for (size_t i = 0; i < preferences && types[i]; i++) {
        selected = select_slice(slices, count, types[i], types[i] == CPU_TYPE_ANY ? CPU_SUBTYPE_ANY : subtypes[i]);
        if (selected >= 0 || types[i] == CPU_TYPE_ANY) break;
    }
    if (selected < 0) return ENOEXEC;
    *image = slices[selected];
    return read_signature(image);
}
