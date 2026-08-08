#ifndef phys_oob_h
#define phys_oob_h

#include "common.h"

void initialize_physical_read_write(mach_vm_size_t contiguous_mapping_size);
kern_return_t physical_oob_read_mo(mach_port_t mo, mach_vm_offset_t mo_offset, uint64_t size, uint64_t offset, uint8_t* buffer);
void physical_oob_read_mo_with_retry(mach_port_t memory_object, mach_vm_offset_t seeking_offset, uint64_t oob_size, uint64_t oob_offset, uint8_t* read_buffer);
void physical_oob_write_mo(mach_port_t mo, mach_vm_offset_t mo_offset, uint64_t size, uint64_t offset, uint8_t* buffer);

#endif /* phys_oob_h */
