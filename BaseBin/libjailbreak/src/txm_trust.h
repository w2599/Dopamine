#ifndef LJB_TXM_TRUST_H
#define LJB_TXM_TRUST_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#define TXM_LOCAL_SIGNING_TRUST 5
struct txm_trust_state {
    uint64_t address;
    uint16_t original;
};

// 与 Relaxin / TrollStoreLite 的 preserve_trust 编码保持一致。
struct __attribute__((packed)) txm_trust_identity {
    uint8_t version, hashType, hashSize, anchorCount;
    uint32_t codeLimit, codeSlotCount;
    int32_t anchorSlots[2];
    uint8_t anchorHashes[2][48];
};
_Static_assert(sizeof(struct txm_trust_identity) == 116, "TXM identity ABI");
struct txm_signing_scope {
    bool team;
    char value[256];
};

bool txm_local_signing_supported(void);
int txm_vnode_trust_address(uint64_t vnode, int64_t sliceOffset, uint64_t *address);
int txm_trust_prepare(uint64_t address, struct txm_trust_state *state);
int txm_trust_restore(const struct txm_trust_state *state);
int txm_trust_validate_process(uint64_t proc, uint64_t vnode, uint64_t address);
int txm_trust_copy_scope(uint64_t address, struct txm_signing_scope *scope);
int txm_trust_library_eligible(uint64_t address, const struct txm_signing_scope *scope,
    const struct txm_trust_identity *preserved, size_t count, bool *eligible);

#endif
