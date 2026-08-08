#ifndef ARM64_H
#define ARM64_H

#include <stdint.h>

static inline uint32_t arm64_decode_ldr_str_off(uint32_t insn) {
    return ((insn >> 10) & 0xFFF) << (insn >> 30);
}

static inline int64_t arm64_decode_ldr_literal_off(uint32_t ldr) {
    int64_t off = (ldr >> 3) & 0x1FFFFC;
    return (off & 0x100000) ? (off | ~0xFFFFFLL) : off;
}

static inline uint64_t arm64_decode_adrp(uint64_t adrp_va, uint32_t adrp) {
    uint64_t immhi = (adrp >> 5)  & 0x7FFFF;
    uint64_t immlo = (adrp >> 29) & 0x3;
    int64_t  imm = (int64_t)(((immhi << 2) | immlo) << 12);
    imm = (imm << 32) >> 32;
    return (adrp_va & ~0xFFFULL) + imm;
}

static inline uint64_t arm64_decode_adrp_add(uint64_t adrp_va, uint32_t adrp, uint32_t add) {
    return arm64_decode_adrp(adrp_va, adrp) + ((add >> 10) & 0xFFF);
}

#endif // ARM64_H
