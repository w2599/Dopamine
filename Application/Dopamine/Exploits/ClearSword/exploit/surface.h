#ifndef surface_h
#define surface_h

#include <CoreFoundation/CoreFoundation.h>

#include "common.h"

CFNumberRef CFNUM(uint64_t value);
IOSurfaceRef create_surface_with_address(mach_vm_address_t address, mach_vm_size_t size);
kern_return_t create_physically_contiguous_mapping(mach_port_t* port_out, mach_vm_address_t* address_out, mach_vm_size_t size);
void surface_mlock(mach_vm_address_t address, mach_vm_size_t size);
void surface_munlock(mach_vm_address_t address);

extern void IOSurfacePrefetchPages(IOSurfaceRef surface);

#endif /* surface_h */
