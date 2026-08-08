#ifndef TRANSLATION_H
#define TRANSLATION_H

#include <stdint.h>
#include "pte.h"

struct tt_level {
	uint64_t offMask;
	uint64_t shift;
	uint64_t indexMask;
	uint64_t validMask;
	uint64_t typeMask;
	uint64_t typeBlock;
};
extern struct tt_level arm_tt_level[4];

uint64_t phystokv(uint64_t pa);
uint64_t vtophys_lvl(uint64_t tte_ttep, uint64_t va, uint64_t *leaf_level, uint64_t *leaf_tte_ttep);
uint64_t vtophys(uint64_t tte_ttep, uint64_t va);
uint64_t kvtophys(uint64_t va);
void libjailbreak_translation_init(void);

#endif