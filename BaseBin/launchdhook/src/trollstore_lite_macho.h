#ifndef TROLLSTORE_LITE_MACHO_H
#define TROLLSTORE_LITE_MACHO_H
#include <stdint.h>
#include <stdbool.h>
#include <fcntl.h>
#include <mach-o/loader.h>
#include <spawn.h>

struct trollstore_lite_macho {
    int fd;
    uint64_t offset, size;
    struct mach_header_64 header;
    fsignatures_t signature;
    uint64_t entitlementOffset;
    uint32_t entitlementSize;
};
int trollstore_lite_macho_read(const struct trollstore_lite_macho *image, uint64_t offset, void *out, size_t size);
int trollstore_lite_macho_find(int fd, const cpu_type_t *types, const cpu_subtype_t *subtypes,
                        size_t count, struct trollstore_lite_macho *image);
#endif
