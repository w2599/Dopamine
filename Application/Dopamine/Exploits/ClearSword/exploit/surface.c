#include "surface.h"

#include <assert.h>

CFNumberRef CFNUM(uint64_t value) {
    return CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &value);  // idc if it leaks
}

IOSurfaceRef create_surface_with_address(mach_vm_address_t address, mach_vm_size_t size) {
    CFMutableDictionaryRef properties = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(properties, CFSTR("IOSurfaceAddress"), CFNUM(address));
    CFDictionarySetValue(properties, CFSTR("IOSurfaceAllocSize"), CFNUM(size));

    IOSurfaceRef surface = IOSurfaceCreate(properties);
    IOSurfacePrefetchPages(surface);  // prefetches all pages for the iosurface ("mlocks" them into memory)
    CFRelease(properties);

    return surface;  // caller owns
}

kern_return_t create_physically_contiguous_mapping(mach_port_t* port_out, mach_vm_address_t* address_out, mach_vm_size_t size) {
    kern_return_t kr = KERN_SUCCESS;

    CFMutableDictionaryRef dict = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(dict, CFSTR("IOSurfaceAllocSize"), CFNUM(size));
    CFDictionarySetValue(dict, CFSTR("IOSurfaceMemoryRegion"), CFSTR("PurpleGfxMem"));

    // create surface in PurpleGfxMem, which is contiguous by nature
    IOSurfaceRef surface = IOSurfaceCreate(dict);
    CFRelease(dict);

    if (surface == NULL) {
        return KERN_FAILURE;
    }

    // get its uaddr
    mach_vm_address_t physical_mapping_address = (mach_vm_address_t)IOSurfaceGetBaseAddress(surface);
    LOG("physical_mapping_address: %#llx", physical_mapping_address);

    // create a memory entry in PurpleGfxMem
    mach_port_t memory_object = MACH_PORT_NULL;
    kr = mach_make_memory_entry_64(mach_task_self(), &size, physical_mapping_address, VM_PROT_DEFAULT, &memory_object, MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) {
        CFRelease(surface);
        return kr;
    }

    // map in PurpleGfxMem
    mach_vm_address_t new_mapping_address = 0;
    kr = mach_vm_map(mach_task_self(), &new_mapping_address, size, 0, VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR, memory_object, 0, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
    CFRelease(surface);
    if (kr != KERN_SUCCESS) {
        mach_port_deallocate(mach_task_self(), memory_object);
        return kr;
    }

    *port_out = memory_object;
    *address_out = new_mapping_address;
    return KERN_SUCCESS;
}

void surface_mlock(mach_vm_address_t address, mach_vm_size_t size) {
    // create surface at address with size, and "mlock" it with IOSurfacePrefetchPages
    IOSurfaceRef surface = create_surface_with_address(address, size);
    size_t idx = g_ctx.mlock_surfaces_count++;
    assert(idx < MAX_LOCKED_SURFACES);
    g_ctx.mlock_surfaces[idx].address = address;
    g_ctx.mlock_surfaces[idx].surface = surface;
}

void surface_munlock(mach_vm_address_t address) {
    // iterate mlocked surfaces until we find a match
    for (size_t idx = 0; idx < g_ctx.mlock_surfaces_count; idx++) {
        if (g_ctx.mlock_surfaces[idx].address == address && g_ctx.mlock_surfaces[idx].surface != NULL) {
            CFRelease(g_ctx.mlock_surfaces[idx].surface);
            g_ctx.mlock_surfaces[idx].surface = NULL;
            g_ctx.mlock_surfaces[idx].address = 0;
            break;
        }
    }
}
