#include "kernel.h"
#include <stdbool.h>
#include "primitives.h"
#include "info.h"
#include "util.h"
#include "codesign.h"
#include <dispatch/dispatch.h>
#include <stdatomic.h>

uint64_t proc_find(pid_t pidToFind)
{
	__block uint64_t foundProc = 0;
	// This sucks a bit due to us not being able to take locks
	// If we don't find anything, just repeat 5 times
	// Attempts to avoids conditions where we got thrown off by modifications
	for (int i = 0; i < 5 && !foundProc; i++) {
		proc_iterate(^(uint64_t proc, bool *stop) {
			pid_t pid = kread32(proc + koffsetof(proc, pid));
			if (pid == pidToFind) {
				foundProc = proc;
				*stop = true;
			}
		});
	}
	return foundProc;
}

int proc_rele(uint64_t proc)
{
	// If proc_find doesn't increment the ref count, there is also no need to decrement it again
	return -1;
}

uint64_t proc_task(uint64_t proc)
{
	if (koffsetof(proc, task)) {
		// iOS <= 15: proc has task attribute
		return kread_ptr(proc + koffsetof(proc, task));
	}
	else {
		// iOS >= 16: task is always at "proc + sizeof(proc)"
		return proc + ksizeof(proc);
	}
}

uint64_t proc_ucred(uint64_t proc)
{
	if (gSystemInfo.kernelStruct.proc_ro.exists) {
		uint64_t proc_ro = kread_ptr(proc + koffsetof(proc, proc_ro));
		return kread_ptr(proc_ro + koffsetof(proc_ro, ucred));
	}
	else {
		return kread_ptr(proc + koffsetof(proc, ucred));
	}
}

uint32_t proc_getcsflags(uint64_t proc)
{
	if (gSystemInfo.kernelStruct.proc_ro.exists) {
		uint64_t proc_ro = kread_ptr(proc + koffsetof(proc, proc_ro));
		return kread32(proc_ro + koffsetof(proc_ro, csflags));
	}
	else {
		return kread32(proc + koffsetof(proc, csflags));
	}
}

void proc_csflags_update(uint64_t proc, uint32_t flags)
{
	if (gSystemInfo.kernelStruct.proc_ro.exists) {
		uint64_t proc_ro = kread_ptr(proc + koffsetof(proc, proc_ro));
		kwrite32(proc_ro + koffsetof(proc_ro, csflags), flags);
	}
	else {
		kwrite32(proc + koffsetof(proc, csflags), flags);
	}
}

void proc_csflags_set(uint64_t proc, uint32_t flags)
{
	proc_csflags_update(proc, proc_getcsflags(proc) | (uint32_t)flags);
}

void proc_csflags_clear(uint64_t proc, uint32_t flags)
{
	proc_csflags_update(proc, proc_getcsflags(proc) & ~(uint32_t)flags);
}

uint64_t ipc_entry_lookup(uint64_t space, mach_port_name_t name)
{
	uint64_t table = 0;
	// New format in iOS 16.1
	if (gSystemInfo.kernelStruct.ipc_space.table_uses_smr) {
		table = kread_smrptr(space + koffsetof(ipc_space, table));
	}
	else {
		table = kread_ptr(space + koffsetof(ipc_space, table));
	}

	return (table + (ksizeof(ipc_entry) * (name >> 8)));
}

uint64_t pa_index(uint64_t pa)
{
	return atop(pa - kread64(ksymbol(vm_first_phys)));
}

uint64_t pai_to_pvh(uint64_t pai)
{
	if (__builtin_available(iOS 27.0, *)) {
		if (ksymbol(SPTMArgs) != 0) {
			uint64_t vm_page = vm_page_for_pai(pai);
			if (!vm_page) return 0;
			return vm_page + koffsetof(vm_page, pv_head);
		}
	}
	return kread64(ksymbol(pv_head_table)) + (pai * 8);
}

struct papt_range_compressed {
	uint64_t startAddr;
	uint64_t baseAddr;
	uint32_t numPages;
	uint32_t __pad;
};

uint64_t pa_to_sptm_root_frame(uint64_t user_root_pt)
{
	unsigned int idx = kread32(ksymbol_sptm(n_papt_ranges_compressed));
	if ( idx )
	{
		struct papt_range_compressed papt_ranges_compressed_l[idx];
		kreadbuf(ksymbol_sptm(papt_ranges_compressed), papt_ranges_compressed_l, sizeof(papt_ranges_compressed_l));

		struct papt_range_compressed *curRange = papt_ranges_compressed_l;
		while ( user_root_pt < curRange->startAddr
				|| curRange->startAddr + ((uint64_t)curRange->numPages << 14) <= user_root_pt )
		{
			++curRange;
			if ( !--idx ) {
				curRange = NULL;
				break;
			}
		}

		if (curRange) {
			uint64_t surt = user_root_pt - curRange->startAddr + curRange->baseAddr;
			if (__builtin_available(iOS 27.0, *)) {
				return (surt & 0xFFFFFFFFFFFFC000LL | (sizeof(struct papt_range_compressed) * ((user_root_pt >> 10) & 0xF)) | 0x3C00);
			}
			else {
				return (surt + 0x40);
			}
		}
	}

	return 0;
}

uint64_t pa_to_sptm_frame(uint64_t pa)
{
	uint64_t candidate = kread64(ksymbol(libsptm_frame_table)) + (pa_index(pa) * 16);
	if (__builtin_available(iOS 19.0, *)) {
		uint8_t type = kread8(candidate + koffsetof(sptm_frame, type));
		// root frames (type 41 on >= 27.0, type 40 on 26.4-26.5, type 17 and 38 on 26.0-26.3.1) need specialized logic

		// If this changes, the change is visible inside acquire_user_root_pt and it's callers:
		//
		// switch ( v7 )
		// {
		// 	case 41:					<---- This is it
		// 	goto LABEL_15;
		// 	case 19:
		// 	v8 = sub_FFFFFFF0270D7DD4();
		// 	goto LABEL_17;
		// 	case 18:
		// LABEL_15:
		// 	v8 = acquire_user_root_pt(a1, a2);
		//
		// Even though case 18 also branches to acquire_user_root_pt, it doesn't require special handling since the function itself checks for "== 41"

		if (__builtin_available(iOS 27.0, *)) {
			if (type == 41) {
				candidate = pa_to_sptm_root_frame(pa);
			}
		}
		else if (__builtin_available(iOS 26.4, *)) {
			if (type == 40) {
				candidate = pa_to_sptm_root_frame(pa);
			}
		}
		else {
			if (type == 17 || type == 38) {
				candidate = pa_to_sptm_root_frame(pa);
			}
		}
	}
	return candidate;
}

uint64_t pvh_ptd(uint64_t pvh)
{
	return ((kread64(pvh) & PVH_LIST_MASK) | kconstant(PVH_HIGH_FLAGS));
}

void task_set_memory_ownership_transfer(uint64_t task, bool value)
{
	kwrite8(task + koffsetof(task, task_can_transfer_memory_ownership), !!value);
}

uint64_t mac_label_get(uint64_t label, int slot)
{
	// On 15.0 - 15.1.1, 0 is the equivalent of -1 on 15.2+
	// So, treat 0 as -1 there
	uint64_t value = kread_ptr(label + ((slot + 1) * sizeof(uint64_t)));
	if (!gSystemInfo.kernelStruct.proc_ro.exists && value == 0) value = -1;
	return value;
}

void mac_label_set(uint64_t label, int slot, uint64_t value)
{
	// THe inverse of the condition above, treat -1 as 0 on 15.0 - 15.1.1
	if (!gSystemInfo.kernelStruct.proc_ro.exists && value == -1) value = 0;
	if (host_is_arm64e()) {
		if (jbinfo(usesPACBypass) && !gSystemInfo.kernelStruct.proc_ro.exists) {
			kcall(NULL, ksymbol(mac_label_set), 3, (uint64_t[]){ label, slot, value });
			return;
		}
	}
	kwrite64(label + ((slot + 1) * sizeof(uint64_t)), value);
}

uint64_t kauth_cred_rw(uint64_t cred)
{
	if (gSystemInfo.kernelStruct.ucred_rw.exists) {
		return kread_ptr(cred + koffsetof(ucred, rw));
	}
	return 0;
}

void kauth_cred_ref(uint64_t ucred)
{
	uint64_t refcntPtr = 0;
	if (gSystemInfo.kernelStruct.ucred_rw.exists) {
		uint64_t ucred_rw = kauth_cred_rw(ucred);
		refcntPtr = ucred_rw + koffsetof(ucred_rw, weak_ref);
	}
	else {
		refcntPtr = ucred + koffsetof(ucred, ref);
	}

	kaccess_mapped(refcntPtr, sizeof(uint64_t), ^(void *ptr){
		_Atomic(uint64_t) *uintPtr = ptr;
		atomic_fetch_add(uintPtr, 1);
	});
}

void kauth_cred_unref(uint64_t ucred)
{
	uint64_t refcntPtr = 0;
	if (gSystemInfo.kernelStruct.ucred_rw.exists) {
		uint64_t ucred_rw = kauth_cred_rw(ucred);
		refcntPtr = ucred_rw + koffsetof(ucred_rw, weak_ref);
	}
	else {
		refcntPtr = ucred + koffsetof(ucred, ref);
	}

	kaccess_mapped(refcntPtr, sizeof(uint64_t), ^(void *ptr){
		_Atomic(uint64_t) *uintPtr = ptr;
		atomic_fetch_sub(uintPtr, 1);
	});
}

void kauth_cred_hold(uint64_t ucred)
{
	if (gSystemInfo.kernelStruct.ucred_rw.exists) {
		uint64_t refcntPtr = ucred + koffsetof(ucred, ref);

		kaccess_mapped(refcntPtr, sizeof(uint64_t), ^(void *ptr){
			_Atomic(uint64_t) *uintPtr = ptr;
			atomic_fetch_add(uintPtr, 1);
		});
	}
}

void kauth_cred_drop(uint64_t ucred)
{
	if (gSystemInfo.kernelStruct.ucred_rw.exists) {
		uint64_t refcntPtr = ucred + koffsetof(ucred, ref);
		
		kaccess_mapped(refcntPtr, sizeof(uint64_t), ^(void *ptr){
			_Atomic(uint64_t) *uintPtr = ptr;
			atomic_fetch_sub(uintPtr, 1);
		});
	}
}

int pmap_cs_allow_invalid(uint64_t pmap)
{
	if (!host_is_arm64e()) return -1;
	if (koffsetof(pmap, txm_address_space)) {
		uint64_t txm_address_space = kread_ptr(pmap + koffsetof(pmap, txm_address_space));
		kwrite8(txm_address_space + koffsetof(TXMAddressSpace, allowsInvalidCode), true);
	}
	else if (koffsetof(pmap, wx_allowed)) {
		kwrite8(pmap + koffsetof(pmap, wx_allowed), true);
	}
	return 0;
}

int cs_allow_invalid(uint64_t proc, bool emulateFully)
{
	if (proc) {
		uint64_t task = proc_task(proc);
		if (task) {
			uint64_t vm_map = kread_ptr(task + koffsetof(task, map));
			if (vm_map) {
				uint64_t pmap = kread_ptr(vm_map + koffsetof(vm_map, pmap));
				if (pmap) {
					// For non-pmap_cs (arm64) devices, this should always be emulated.
					if (emulateFully || !host_is_arm64e()) {
						// Fugu15 Rootful
						//proc_csflags_clear(proc, CS_EXEC_SET_ENFORCEMENT | CS_EXEC_SET_KILL | CS_EXEC_SET_HARD | CS_REQUIRE_LV | CS_ENFORCEMENT | CS_RESTRICT | CS_KILL | CS_HARD | CS_FORCED_LV);
						//proc_csflags_set(proc, CS_DEBUGGED | CS_INVALID_ALLOWED | CS_GET_TASK_ALLOW);

						// XNU
						proc_csflags_clear(proc, CS_KILL | CS_HARD);
						proc_csflags_set(proc, CS_DEBUGGED);

						task_set_memory_ownership_transfer(task, true);
						vm_map_flags flags = { 0 };
						kreadbuf(vm_map + koffsetof(vm_map, flags), &flags, sizeof(flags));
						flags.switch_protect = false;
						flags.cs_debugged = true;
						kwritebuf(vm_map + koffsetof(vm_map, flags), &flags, sizeof(flags));
					}
					// For pmap_cs (arm64e) devices, this is enough to get unsigned code to run
					pmap_cs_allow_invalid(pmap);
				}
			}
		}
	}
	return 0;
}

kern_return_t pmap_enter_options_addr(uint64_t pmap, uint64_t pa, uint64_t va)
{
	uint64_t kr = -1;
	if (!is_kcall_available()) return kr;
	while (1) {
		kcall(&kr, ksymbol(pmap_enter_options_addr), 8, (uint64_t[]){ pmap, va, pa, VM_PROT_READ | VM_PROT_WRITE, 0, 0, 1, 1 });
		if (kr != KERN_RESOURCE_SHORTAGE) {
			return kr;
		}
	}
}

uint64_t pmap_remove_options(uint64_t pmap, uint64_t start, uint64_t end)
{
	uint64_t r = -1;
	if (!is_kcall_available()) return r;
	kcall(&r, ksymbol(pmap_remove_options), 4, (uint64_t[]){ pmap, start, end, 0x100 });
	return r;
}

void pmap_remove(uint64_t pmap, uint64_t start, uint64_t end)
{
	if (host_is_arm64e()) {
		pmap_remove_options(pmap, start, end);
	} else {
		uint64_t remove_count = 0;
		if (!pmap) {
			return;
		}
		uint64_t va = start;
		while (va < end) {
			uint64_t l;
			l = ((va + L2_BLOCK_SIZE) & ~L2_BLOCK_MASK);
			if (l > end) {
				l = end;
			}
			remove_count = pmap_remove_options(pmap, va, l);
			va = remove_count;
		}
	}
}

static inline uint64_t VM_PAGE_UNPACK_PTR(uint32_t packed)
{
	if (packed == 0)
		return 0;
	return ((uint64_t)packed << kconstant(VM_PAGE_PACKED_PTR_SHIFT)) + kconstant(VM_PAGE_PACKED_PTR_BASE);
}

// iOS 27.0+ ONLY
uint64_t vm_page_find_canonical_radix(uint64_t pnum)
{
	uint32_t pmap_first_pnum     = kread32(ksymbol(pmap_first_pnum));
	uint64_t vm_pages_radix_root = kread64(ksymbol(vm_pages_radix_root));

	int      depth = (int)(vm_pages_radix_root & 7);
	uint64_t node  = vm_pages_radix_root & ~7ULL;

	if (pnum < pmap_first_pnum) {
		return 0;
	}

	uint32_t idx = (uint32_t)(pnum - pmap_first_pnum);

	if (node == 0) {
		return 0;
	}

	for (int level = depth; level >= 1; level--) {
		uint32_t slot  = (uint32_t)(((uint64_t)idx >> (8 * level)) & 0xFF);
		uint64_t addr  = node + 4ULL * slot;
		uint32_t entry = kread32(addr);

		if (entry == 0) {
			return 0;
		}
		node = VM_PAGE_UNPACK_PTR(entry);
	}

	uint32_t leaf_slot  = idx & 0xFF;
	uint64_t leaf_addr  = node + (4ULL * leaf_slot);
	uint32_t leaf_entry = kread32(leaf_addr);

	if (leaf_entry == 0) {
		return 0;
	}

   	return VM_PAGE_UNPACK_PTR(leaf_entry);
}