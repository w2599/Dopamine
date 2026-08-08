#ifndef PHYSRW_PTE_H
#define PHYSRW_PTE_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

#include "info.h"
#define MAGIC_PT_ADDRESS (L1_BLOCK_SIZE * (L1_BLOCK_COUNT - 3))
#define gMagicPT ((uint64_t *)MAGIC_PT_ADDRESS) // fake variable

int physrw_pte_handoff(pid_t pid, uint64_t *asidPtr);
int libjailbreak_physrw_pte_init(bool receivedHandoff, uint64_t asidPtr);
bool device_supports_physrw_pte(void);

#endif