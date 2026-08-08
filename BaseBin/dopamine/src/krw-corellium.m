#include <libjailbreak/info.h>
#include <libjailbreak/primitives_external.h>
#include <libjailbreak/translation.h>
#include "corellium.h"

static int kreadbuf_wrapper(uint64_t kaddr, void* output, size_t size)
{
	return unicopy(UNICOPY_DST_USER | UNICOPY_SRC_KERN, (uintptr_t)output, (uintptr_t)kaddr, size) == size;
}

static int kwritebuf_wrapper(uint64_t kaddr, const void* input, size_t size)
{
	return unicopy(UNICOPY_DST_KERN | UNICOPY_SRC_USER, (uintptr_t)kaddr, (uintptr_t)input, size) == size;
}

static int physreadbuf_wrapper(uint64_t pa, void* output, size_t size)
{
	return unicopy(UNICOPY_DST_USER | UNICOPY_SRC_PHYS, (uintptr_t)output, (uintptr_t)pa, size) == size;
}

static int physwritebuf_wrapper(uint64_t pa, const void* input, size_t size)
{
	return unicopy(UNICOPY_DST_PHYS | UNICOPY_SRC_USER, (uintptr_t)pa, (uintptr_t)input, size) == size;
}

int corellium_krw_init(void)
{
	uint64_t kernelBase = get_kern_info(KERN_INFO_VA);
	gSystemInfo.kernelConstant.slide = kernelBase - kconstant(staticBase);

	gPrimitives.kreadbuf = kreadbuf_wrapper;
	gPrimitives.kwritebuf = kwritebuf_wrapper;
	gPrimitives.physreadbuf = physreadbuf_wrapper;
	gPrimitives.physwritebuf = physwritebuf_wrapper;

    gPrimitives.phystokv = phystokv;

	return 0;
}