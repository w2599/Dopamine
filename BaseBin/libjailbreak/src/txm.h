#ifndef LJB_TXM_H
#define LJB_TXM_H

#include "tree_krw.h"
#include "translation.h"

enum {
	kTXMCodeRegionTypeExecutable=0,
	kTXMCodeRegionTypeSharedRegion=1,
	kTXMCodeRegionTypeJIT=2,
	kTXMCodeRegionTypeDebug=3
};

// Basically we need a kernel address that at + koffsetof(TXMCodeRegion, startAddr) has the adress we want to search for
// This produces it by just translating the userspace address to kernelspace and substracting the offset
#define CodeRegionRBTree_KEY(x) (phystokv(vtophys(ttep_self(), (uint64_t)&x)) - koffsetof(TXMCodeRegion, startAddr))

RB_PROTOTYPE(TXMCodeRegionRBTree, uint64_t, koffsetof(TXMCodeRegion, RBLink), TXMCodeRegion_comparator)

uint64_t allocateCodeRegionObject(void);

#endif