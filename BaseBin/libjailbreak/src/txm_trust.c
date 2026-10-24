#include "txm_trust.h"
#include "kernel.h"
#include "primitives.h"
#include <errno.h>
#include <libkern/OSCacheControl.h>

// 只使用已经确认布局的 TXM 版本，未知版本保留原启动行为。
bool txm_local_signing_supported(void)
{
	return ksymbol(SPTMArgs) && koffsetof(pmap, txm_address_space)
		&& koffsetof(TXMAddressSpace, mainRegion)
		&& koffsetof(TXMCodeRegion, codeSignature)
		&& koffsetof(TXMCodeSignature, codeDirectory)
		&& koffsetof(TXMCodeSignature, trustPair);
}

// 检查每一级指针，避免读失败或布局错误时继续访问低地址。
static int txm_read_pointer(uint64_t address, uint64_t *pointer)
{
	uint64_t raw = 0;
	if (kreadbuf(address, &raw, sizeof(raw)) != 0) return EIO;
	*pointer = UNSIGN_PTR(raw);
	uint64_t mask = kconstant(pointer_mask);
	return *pointer && mask && (*pointer & mask) == mask ? 0 : EFAULT;
}

// 在子进程恢复前调整主签名；不遍历或改写框架及保留信任的附加签名。
int proc_set_txm_main_local_signing_trust(uint64_t proc)
{
	if (!txm_local_signing_supported()) return ENOTSUP;
	if (!proc) return ESRCH;
	uint64_t task = proc_task(proc), map, pmap, space, region, signature, directory;
	if (!task) return EFAULT;
	int status = txm_read_pointer(task + koffsetof(task, map), &map);
	if (status) return status;
	status = txm_read_pointer(map + koffsetof(vm_map, pmap), &pmap);
	if (status) return status;
	status = txm_read_pointer(pmap + koffsetof(pmap, txm_address_space), &space);
	if (status) return status;
	status = txm_read_pointer(space + koffsetof(TXMAddressSpace, mainRegion), &region);
	if (status) return status;
	status = txm_read_pointer(region + koffsetof(TXMCodeRegion, codeSignature), &signature);
	if (status) return status;
	status = txm_read_pointer(signature + koffsetof(TXMCodeSignature, codeDirectory), &directory);
	if (status) return status;
	uint32_t magic = 0;
	if (kreadbuf(directory, &magic, sizeof(magic)) != 0) return EIO;
	if (__builtin_bswap32(magic) != 0xfade0c02) return ENOEXEC;

	uint64_t address = signature + koffsetof(TXMCodeSignature, trustPair);
	if (address & (sizeof(uint16_t) - 1)) return EFAULT;
	uint16_t pair = 0;
	if (kreadbuf(address, &pair, sizeof(pair)) != 0) return EIO;
	uint8_t trust = pair & 0xff, forkTrust = pair >> 8;
	if (trust != forkTrust) return EBUSY;
	if (trust <= 5) return 0;
	if (trust >= 10) return ENOTSUP;

	// PMAP_CS_LOCAL_SIGNING 为 5；同步物理别名缓存后回读确认。
	__block int writeStatus = EIO;
	status = kaccess_mapped(address, sizeof(pair), ^(void *mapped) {
		volatile uint16_t *value = mapped;
		if (*value != pair) { writeStatus = EBUSY; return; }
		*value = 0x0505;
		sys_dcache_flush(mapped, sizeof(pair));
		__asm__ volatile("dsb sy" ::: "memory");
		writeStatus = *value == 0x0505 ? 0 : EIO;
	});
	return status == 0 ? writeStatus : EIO;
}
