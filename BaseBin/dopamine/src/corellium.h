#define KERN_INFO_VA 0x00
#define KERN_INFO_PA 0x01
 
#define KERN_INFO_TPIDR_EL1 0x40
#define KERN_INFO_TTBR0_EL1 0x41
#define KERN_INFO_TTBR1_EL1 0x42
#define KERN_INFO_TCR_EL1 0x43
#define KERN_INFO_VBAR_EL1 0x44
#define KERN_INFO_CONTEXTIDR_EL1 0x45
 
// access kernel-specific information based on the specified KERN_INFO_* parameter
uintptr_t get_kern_info(unsigned int key);
 
#define UNICOPY_DST_USER 0 // Copy to user virtual address space
#define UNICOPY_DST_KERN 1 // Copy to kernel virtual address space
#define UNICOPY_DST_PHYS 2 // Copy to physical address
#define UNICOPY_SRC_USER 0 // Copy from user virtual address space
#define UNICOPY_SRC_KERN 4 // Copy from kernel address space
#define UNICOPY_SRC_PHYS 8 // Copy from physical address
 
// returns amount of data copied successfully
// mode: the bitwise OR of a UNICOPY_DST_* and UNICOPY_SRC* parameter, specifying the// address space to copy to and from.
// dst: the address to copy to in the UNICODE_DST_* address space
// src: the address to copy from in the UNICODE_SRC_* address space
// size: the number of bytes to copy from one address space to the other.
size_t unicopy(unsigned int mode, uintptr_t dst, uintptr_t src, size_t size);