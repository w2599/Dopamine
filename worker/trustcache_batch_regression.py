#!/usr/bin/env python3
"""编译实际 TrustCache 源函数，用内存桩验证跨页追加与失败路径。"""

import argparse
import os
from pathlib import Path
import resource
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "BaseBin/libjailbreak/src/trustcache.c"
STRUCTS = ROOT / "BaseBin/libjailbreak/src/trustcache_structs.h"

PRELUDE = r"""
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <uuid/uuid.h>

#define CS_CDHASH_LEN 20
"""

STUBS = r"""
#define MAX_PAGES 256
#define ROOT_ADDRESS UINT64_C(0x1000)
#define RUNTIME_ADDRESS UINT64_C(0x2000)
#define FIRST_PAGE UINT64_C(0x100000)
#define ksymbol(name) symbol_##name
#define ksymbol_txm(name) symbol_##name
#define koffsetof(type, field) offset_##field
#define ksizeof(type) 0x40

static uint64_t symbol_pmap_image4_trust_caches = ROOT_ADDRESS;
static uint64_t symbol_ppl_trust_cache_rt;
static uint64_t symbol_txm_trustcache_root;
static uint64_t symbol_SPTMArgs;
static size_t offset_nextptr = 0;
static size_t offset_prevptr = 8;
static size_t offset_fileptr = 0x20;
static size_t offset_size = 0x28;
static size_t offset_type = 0x30;

static struct {
    bool allocated;
    _Alignas(16) unsigned char data[JB_TRUSTCACHE_SIZE];
} pages[MAX_PAGES];
static uint64_t head;
static uint64_t runtime_head_address = ROOT_ADDRESS;
static unsigned page_slots, kalloc_calls, free_calls;
static unsigned read_calls, write_calls, write64_calls;
static unsigned invalid_reads, invalid_writes;
static unsigned user_alloc_calls, live_user_buffers, peak_user_buffers;
static bool fail_user_alloc, fail_kernel_alloc, return_zero_address;
static bool fail_length_read, fail_full_read, fail_full_write, fail_header_write;
static unsigned fail_write64_call, fail_write64_call_2, commit_failed_write64_call;
static uint64_t fail_read_address, fail_buf_write_address;
static unsigned fail_read_remaining;
static uint64_t concurrent_write_address, concurrent_write_value;

// 将模拟地址解析为页内存，拒绝所有越界或已释放的访问。
static void *resolve(uint64_t address, size_t size)
{
    if (address < FIRST_PAGE) return NULL;
    uint64_t delta = address - FIRST_PAGE;
    size_t index = delta / JB_TRUSTCACHE_SIZE;
    size_t offset = delta % JB_TRUSTCACHE_SIZE;
    if (index >= page_slots || !pages[index].allocated
        || size > JB_TRUSTCACHE_SIZE - offset) return NULL;
    return pages[index].data + offset;
}

// 模拟分配内核页，也覆盖返回成功但地址为空的异常情况。
static int kalloc(uint64_t *out, uint64_t size)
{
    assert(size > 0 && size <= JB_TRUSTCACHE_SIZE);
    kalloc_calls++;
    *out = 0;
    if (fail_kernel_alloc) return ENOMEM;
    if (return_zero_address) return 0;
    assert(page_slots < MAX_PAGES);
    pages[page_slots].allocated = true;
    memset(pages[page_slots].data, 0, JB_TRUSTCACHE_SIZE);
    *out = FIRST_PAGE + page_slots++ * JB_TRUSTCACHE_SIZE;
    return 0;
}

// 记录未发布页的释放，不允许释放当前链表头。
static int kfree(uint64_t address, uint64_t size)
{
    assert(size > 0 && size <= JB_TRUSTCACHE_SIZE);
    unsigned visited = 0;
    for (uint64_t current = head; current;) {
        assert(++visited <= MAX_PAGES && current != address);
        unsigned char *memory = resolve(current, ksizeof(trustcache));
        assert(memory);
        uint64_t prev = 0;
        if (offset_prevptr) memcpy(&prev, memory + offset_prevptr, sizeof(prev));
        assert(prev != address);
        memcpy(&current, memory + offset_nextptr, sizeof(current));
    }
    assert(resolve(address, size));
    pages[(address - FIRST_PAGE) / JB_TRUSTCACHE_SIZE].allocated = false;
    free_calls++;
    return 0;
}

// 注入读取失败，保证被测函数不会把错误当成空页。
static int kreadbuf(uint64_t address, void *out, size_t size)
{
    read_calls++;
    if (address == fail_read_address && fail_read_remaining) {
        fail_read_remaining--;
        memset(out, 0, size);
        return EIO;
    }
    if (address == RUNTIME_ADDRESS + 0x20 && size == sizeof(runtime_head_address)) {
        memcpy(out, &runtime_head_address, size);
        return 0;
    }
    if (address == ROOT_ADDRESS && size == sizeof(head)) {
        memcpy(out, &head, size);
        return 0;
    }
    void *memory = resolve(address, size);
    if (!memory) { invalid_reads++; return EFAULT; }
    if ((fail_length_read && size == sizeof(uint32_t)
         && (address - FIRST_PAGE) % JB_TRUSTCACHE_SIZE == offsetof(jb_trustcache, file.length))
        || (fail_full_read && size == JB_TRUSTCACHE_SIZE)) return EIO;
    memcpy(out, memory, size);
    return 0;
}

// 模拟签名页及链表写入；任何零地址写入都会被测试检测。
static int kwritebuf(uint64_t address, const void *in, size_t size)
{
    write_calls++;
    if (address == fail_buf_write_address) return EIO;
    if (address == ROOT_ADDRESS && size == sizeof(head)) {
        memcpy(&head, in, size);
        return 0;
    }
    void *memory = resolve(address, size);
    if (!memory) { invalid_writes++; return EFAULT; }
    if ((fail_full_write && size == JB_TRUSTCACHE_SIZE)
        || (fail_header_write && size == sizeof(jb_trustcache))) return EIO;
    memcpy(memory, in, size);
    return 0;
}

// 保留真实代码对标量读取失败的既有接口语义。
static uint64_t kread64(uint64_t address)
{
    uint64_t value = 0;
    kreadbuf(address, &value, sizeof(value));
    return value;
}

// 兼容修复前上传实现，用于验证旧版本确实触发故障断言。
static uint32_t kread32(uint64_t address)
{
    uint32_t value = 0;
    kreadbuf(address, &value, sizeof(value));
    return value;
}

// 为真实插链函数提供可注入的标量写入错误。
static int kwrite64(uint64_t address, uint64_t value)
{
    write64_calls++;
    if (fail_write64_call == write64_calls || fail_write64_call_2 == write64_calls) {
        if (commit_failed_write64_call == write64_calls) {
            assert(kwritebuf(address, &value, sizeof(value)) == 0);
        }
        if (concurrent_write_address) {
            assert(kwritebuf(concurrent_write_address, &concurrent_write_value, sizeof(concurrent_write_value)) == 0);
            concurrent_write_address = 0;
        }
        return EIO;
    }
    return kwritebuf(address, &value, sizeof(value));
}

// 记录临时缓冲的峰值数量，检查批次没有按页累积内存。
static void *tracked_malloc(size_t size)
{
    user_alloc_calls++;
    assert(size == JB_TRUSTCACHE_SIZE);
    if (fail_user_alloc) return NULL;
    void *memory = malloc(size);
    assert(memory);
    live_user_buffers++;
    if (live_user_buffers > peak_user_buffers) peak_user_buffers = live_user_buffers;
    return memory;
}

// 确认每条成功和失败路径均释放临时缓冲。
static void tracked_free(void *memory)
{
    if (memory) { assert(live_user_buffers); live_user_buffers--; }
    free(memory);
}

#define malloc tracked_malloc
#define free tracked_free
"""

TESTS = r"""
#undef malloc
#undef free

// 清空模拟内核及所有故障注入状态。
static void reset(void)
{
    assert(live_user_buffers == 0);
    memset(pages, 0, sizeof(pages));
    head = 0;
    page_slots = kalloc_calls = free_calls = 0;
    read_calls = write_calls = write64_calls = 0;
    invalid_reads = invalid_writes = 0;
    user_alloc_calls = live_user_buffers = peak_user_buffers = 0;
    fail_user_alloc = fail_kernel_alloc = return_zero_address = false;
    fail_length_read = fail_full_read = fail_full_write = fail_header_write = false;
    fail_write64_call = fail_write64_call_2 = commit_failed_write64_call = 0;
    fail_read_address = fail_buf_write_address = 0;
    fail_read_remaining = 0;
    concurrent_write_address = concurrent_write_value = 0;
    symbol_SPTMArgs = symbol_ppl_trust_cache_rt = symbol_txm_trustcache_root = 0;
    symbol_pmap_image4_trust_caches = runtime_head_address = ROOT_ADDRESS;
}

// 使用按字节排序的唯一散列，便于独立检查无重复和无遗漏。
static struct trustcache_entry_v1 make_entry(uint32_t key)
{
    struct trustcache_entry_v1 entry = {0};
    entry.hash[0] = key >> 24;
    entry.hash[1] = key >> 16;
    entry.hash[2] = key >> 8;
    entry.hash[3] = key;
    entry.hash_type = 1;
    return entry;
}

// 从散列恢复唯一编号。
static uint32_t entry_key(const struct trustcache_entry_v1 *entry)
{
    return ((uint32_t)entry->hash[0] << 24) | ((uint32_t)entry->hash[1] << 16)
        | ((uint32_t)entry->hash[2] << 8) | entry->hash[3];
}

// 建立已有缓存页，模拟当前页只剩少量空间。
static void seed_page(uint32_t count)
{
    uint64_t address = 0;
    assert(_jb_trustcache_grow(&address) == 0);
    jb_trustcache *page = resolve(address, JB_TRUSTCACHE_SIZE);
    assert(count <= JB_TRUSTCACHE_ENTRY_COUNT);
    page->file.length = count;
    for (uint32_t i = 0; i < count; i++) page->file.entries[i] = make_entry(i);
    read_calls = write_calls = write64_calls = 0;
}

// 独立遍历输出，验证旧条目保留、新条目恰好一次且每页排序有效。
static void verify(uint32_t expected)
{
    bool *seen = calloc(expected ? expected : 1, sizeof(bool));
    assert(seen);
    uint32_t total = 0;
    unsigned visited = 0;
    uint64_t previous = 0;
    for (uint64_t address = head; address;) {
        assert(++visited <= MAX_PAGES);
        jb_trustcache *page = resolve(address, JB_TRUSTCACHE_SIZE);
        assert(page && page->file.length <= JB_TRUSTCACHE_ENTRY_COUNT);
        uint64_t prev = 0;
        if (offset_prevptr) memcpy(&prev, page->trustcache + offset_prevptr, sizeof(prev));
        assert(prev == previous);
        for (uint32_t i = 0; i < page->file.length; i++) {
            uint32_t key = entry_key(&page->file.entries[i]);
            assert(key < expected && !seen[key]);
            assert(page->file.entries[i].hash_type == 1);
            if (i) assert(memcmp(page->file.entries[i-1].hash,
                                 page->file.entries[i].hash, CS_CDHASH_LEN) <= 0);
            seen[key] = true;
            total++;
        }
        previous = address;
        memcpy(&address, page->trustcache + offset_nextptr, sizeof(address));
    }
    assert(total == expected);
    for (uint32_t i = 0; i < expected; i++) assert(seen[i]);
    assert(!invalid_reads && !invalid_writes && !live_user_buffers);
    free(seen);
}

// 从真实批量函数追加跨页数据。
static void test_batch(uint32_t existing, uint32_t count)
{
    reset();
    if (existing) seed_page(existing);
    struct trustcache_entry_v1 *entries = malloc(count * sizeof(*entries));
    assert(entries);
    for (uint32_t i = 0; i < count; i++) entries[i] = make_entry(existing+i);
    assert(jb_trustcache_add_entries(entries, count) == 0);
    verify(existing+count);
    assert(user_alloc_calls == 1 && peak_user_buffers == 1);
    free(entries);
}

// 验证公开散列入口同样使用有界转换缓冲并正确跨页。
static void test_hash_wrapper(void)
{
    reset();
    seed_page(JB_TRUSTCACHE_ENTRY_COUNT-2);
    uint32_t count = JB_TRUSTCACHE_ENTRY_COUNT*3+11;
    cdhash_t *hashes = malloc(count * sizeof(*hashes));
    assert(hashes);
    for (uint32_t i = 0; i < count; i++) {
        struct trustcache_entry_v1 entry = make_entry(JB_TRUSTCACHE_ENTRY_COUNT-2+i);
        memcpy(hashes[i], entry.hash, sizeof(cdhash_t));
    }
    assert(jb_trustcache_add_cdhashes(hashes, count) == 0);
    verify(JB_TRUSTCACHE_ENTRY_COUNT-2+count);
    assert(peak_user_buffers == 1);
    free(hashes);
}

// 验证空批、非法输入以及单条入口的边界语义。
static void test_input_edges(void)
{
    reset();
    assert(jb_trustcache_add_entries(NULL, 0) == 0);
    assert(jb_trustcache_add_cdhashes(NULL, 0) == 0);
    assert(jb_trustcache_add_entries(NULL, 1) == EINVAL);
    assert(jb_trustcache_add_cdhashes(NULL, 1) == EINVAL);
    assert(!user_alloc_calls && !kalloc_calls && !read_calls && !write_calls);
    struct trustcache_entry_v1 entry = make_entry(0);
    assert(jb_trustcache_add_entry(entry) == 0);
    verify(1);
}

// 验证分配失败及无效地址不会进入内核读写。
static void test_alloc_failures(void)
{
    struct trustcache_entry_v1 entry = make_entry(0);
    reset();
    fail_user_alloc = true;
    assert(jb_trustcache_add_entries(&entry, 1) == ENOMEM);
    assert(!kalloc_calls && !write_calls);
    verify(0);
    reset();
    fail_kernel_alloc = true;
    assert(jb_trustcache_add_entries(&entry, 1) == ENOMEM);
    assert(!write_calls);
    verify(0);
    reset();
    return_zero_address = true;
    assert(jb_trustcache_add_entries(&entry, 1) == ENOMEM);
    assert(!write_calls);
    verify(0);
    reset();
    fail_header_write = true;
    assert(jb_trustcache_add_entries(&entry, 1) == EIO);
    assert(free_calls == 1 && !head);
    verify(0);
}

// 验证插链失败被真实插链、扩容及追加函数逐层上报。
static void test_link_failures(void)
{
    struct trustcache_entry_v1 entry = make_entry(0);
    reset();
    fail_write64_call = 2;
    assert(jb_trustcache_add_entries(&entry, 1) == EIO);
    assert(!head);
    verify(0);
    reset();
    symbol_SPTMArgs = 1;
    assert(jb_trustcache_add_entries(&entry, 1) == ENOENT);
    assert(!head && !invalid_writes);
    verify(0);
}

// 验证读取、写入及损坏长度都能中止追加并保留原条目。
static void test_io_failures(void)
{
    struct trustcache_entry_v1 entry = make_entry(3);
    reset(); seed_page(3); fail_length_read = true;
    assert(jb_trustcache_add_entries(&entry, 1) == EIO);
    assert(!write_calls); verify(3);
    reset(); seed_page(3); fail_full_read = true;
    assert(jb_trustcache_add_entries(&entry, 1) == EIO);
    assert(!write_calls); verify(3);
    reset(); seed_page(3); fail_full_write = true;
    assert(jb_trustcache_add_entries(&entry, 1) == EIO);
    verify(3);
    reset(); seed_page(3);
    jb_trustcache *page = resolve(head, JB_TRUSTCACHE_SIZE);
    page->file.length = JB_TRUSTCACHE_ENTRY_COUNT+1;
    assert(jb_trustcache_add_entries(&entry, 1) == EINVAL);
    assert(!write_calls && !live_user_buffers);
    page->file.length = 3;
    verify(3);
}

// 跨页中途失败允许已提交页保留，但必须报错且不能写无效地址。
static void test_partial_failure(void)
{
    reset(); seed_page(JB_TRUSTCACHE_ENTRY_COUNT-1);
    struct trustcache_entry_v1 entries[3];
    for (uint32_t i = 0; i < 3; i++) entries[i] = make_entry(JB_TRUSTCACHE_ENTRY_COUNT-1+i);
    fail_kernel_alloc = true;
    assert(jb_trustcache_add_entries(entries, 3) == ENOMEM);
    verify(JB_TRUSTCACHE_ENTRY_COUNT);
}

// 检查根、后继及页识别读取失败不会触发扩容或修改现存链接。
static void test_link_read_failures(void)
{
    struct trustcache_entry_v1 entry = make_entry(1);
    const size_t offsets[] = { offset_fileptr, offsetof(jb_trustcache, magic) };
    for (unsigned i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++) {
        reset(); seed_page(1);
        fail_read_address = head + offsets[i]; fail_read_remaining = 1;
        assert(jb_trustcache_add_entries(&entry, 1) == EIO);
        assert(kalloc_calls == 1 && !write_calls);
        verify(1);
    }
    reset(); seed_page(1);
    fail_read_address = ROOT_ADDRESS; fail_read_remaining = 1;
    assert(jb_trustcache_add_entries(&entry, 1) == EIO);
    assert(kalloc_calls == 1 && !write_calls); verify(1);
}

// PPL 和 TXM 间接根读取失败、空根地址与未配置符号都必须中止修改。
static void test_indirect_root_failures(void)
{
    struct trustcache_entry_v1 entry = make_entry(1);
    for (unsigned txm = 0; txm < 2; txm++) {
        reset(); seed_page(1);
        symbol_pmap_image4_trust_caches = 0;
        if (txm) symbol_txm_trustcache_root = RUNTIME_ADDRESS;
        else symbol_ppl_trust_cache_rt = RUNTIME_ADDRESS;
        fail_read_address = RUNTIME_ADDRESS + 0x20; fail_read_remaining = 1;
        assert(jb_trustcache_add_entries(&entry, 1) == EIO);
        assert(kalloc_calls == 1 && !write_calls);
        runtime_head_address = 0;
        assert(jb_trustcache_add_entries(&entry, 1) == EFAULT);
        assert(kalloc_calls == 1 && !write_calls);
        runtime_head_address = ROOT_ADDRESS;
        verify(1);
    }
    reset(); symbol_pmap_image4_trust_caches = 0;
    assert(jb_trustcache_add_entries(&entry, 1) == ENOTSUP);
    assert(!kalloc_calls && !write_calls);
}

// 尾指针读取错误必须中止插链，不能覆盖原有后继。
static void test_tail_read_failure(void)
{
    reset(); seed_page(1);
    uint64_t oldHead = head, added = 0;
    assert(_jb_trustcache_grow(&added) == 0);
    uint64_t newHead = head;
    symbol_SPTMArgs = 1;
    fail_read_address = newHead + offset_nextptr; fail_read_remaining = 1;
    write64_calls = 0;
    assert(_jb_trustcache_grow(&added) == EIO);
    assert(!added && !write64_calls);
    assert(head == newHead && kread64(newHead + offset_nextptr) == oldHead);
    verify(1);
}

// 检查根写失败及写入后报错均恢复原头和原始反向链接。
static void test_head_insert_rollback(void)
{
    for (unsigned committed = 0; committed < 2; committed++) {
        reset(); seed_page(1);
        uint64_t oldHead = head, added = 0;
        fail_write64_call = 3;
        commit_failed_write64_call = committed ? 3 : 0;
        assert(_jb_trustcache_grow(&added) == EIO);
        assert(!added && head == oldHead && !free_calls);
        verify(1);
    }
    reset(); seed_page(1);
    uint64_t originalPrev = UINT64_C(0x123400);
    memcpy((unsigned char *)resolve(head, JB_TRUSTCACHE_SIZE) + offset_prevptr,
           &originalPrev, sizeof(originalPrev));
    fail_write64_call = 3;
    uint64_t added = 0;
    assert(_jb_trustcache_grow(&added) == EIO);
    assert(kread64(head + offset_prevptr) == originalPrev);
}

// 回滚写失败时保留仍被链表引用的页；未知并发新值不得被覆盖。
static void test_rollback_failures(void)
{
    reset(); seed_page(1);
    uint64_t oldHead = head, added = 0;
    fail_write64_call = 3; commit_failed_write64_call = 3;
    fail_write64_call_2 = 4;
    assert(_jb_trustcache_grow(&added) == EIO);
    assert(!added && head != oldHead && !free_calls);
    assert(resolve(head, JB_TRUSTCACHE_SIZE));
    assert(kread64(head + offset_nextptr) == oldHead);
    verify(1);

    reset(); seed_page(1);
    oldHead = head;
    fail_write64_call = 3; fail_write64_call_2 = 4;
    assert(_jb_trustcache_grow(&added) == EIO);
    uint64_t retained = kread64(oldHead + offset_prevptr);
    assert(!added && head == oldHead && retained && !free_calls);
    assert(resolve(retained, JB_TRUSTCACHE_SIZE));

    reset(); seed_page(1);
    oldHead = head;
    uint64_t third = 0;
    assert(kalloc(&third, JB_TRUSTCACHE_SIZE) == 0);
    fail_write64_call = 3;
    concurrent_write_address = ROOT_ADDRESS; concurrent_write_value = third;
    assert(_jb_trustcache_grow(&added) == EBUSY);
    assert(head == third && !free_calls && !added);
}

// 尾插发布失败或写入后报错均保留原尾，回滚失败也不释放新页。
static void test_tail_insert_rollback(void)
{
    for (unsigned rollbackFails = 0; rollbackFails < 2; rollbackFails++) {
        reset(); seed_page(1);
        uint64_t oldHead = head, added = 0;
        symbol_SPTMArgs = 1;
        fail_write64_call = 2; commit_failed_write64_call = 2;
        if (rollbackFails) fail_write64_call_2 = 3;
        assert(_jb_trustcache_grow(&added) == EIO);
        assert(!added && !free_calls);
        uint64_t next = kread64(oldHead + offset_nextptr);
        assert(rollbackFails ? next != 0 : next == 0);
        if (next) assert(resolve(next, JB_TRUSTCACHE_SIZE));
        verify(1);
    }
}

// 摘链时传播读取失败，并回滚已更新的正向链接和反向链接。
static void test_remove_failures(void)
{
    reset(); seed_page(1);
    uint64_t oldHead = head, added = 0;
    assert(_jb_trustcache_grow(&added) == 0);
    fail_read_address = added + offset_nextptr; fail_read_remaining = 1;
    assert(trustcache_list_remove(oldHead) == EIO);
    verify(1);
    write64_calls = 0;
    fail_write64_call = 2; commit_failed_write64_call = 2;
    assert(trustcache_list_remove(added) == EIO);
    assert(head == added && !free_calls);
    verify(1);
}

// 创建独立缓存，确保测试覆盖实际文件上传函数而非包装桩。
static trustcache_file_v1 *make_file(uint32_t count)
{
    trustcache_file_v1 *file = calloc(1, sizeof(*file) + count * sizeof(trustcache_entry_v1));
    assert(file);
    _trustcache_file_init(file);
    file->length = count;
    for (uint32_t i = 0; i < count; i++) file->entries[i] = make_entry(i);
    return file;
}

// 文件上传的查找、初始化、插链和替换失败均返回错误并保留被引用页。
static void test_file_upload_failures(void)
{
    trustcache_file_v1 *file = make_file(1);
    reset(); fail_read_address = ROOT_ADDRESS; fail_read_remaining = 1;
    assert(trustcache_file_upload(file) == EIO && !kalloc_calls);
    reset(); fail_buf_write_address = FIRST_PAGE;
    assert(trustcache_file_upload(file) == EIO && free_calls == 1 && !head);
    reset(); fail_write64_call = 5;
    assert(trustcache_file_upload(file) == EIO && !head && !free_calls);
    reset(); assert(trustcache_file_upload(file) == 0);
    uint64_t oldHead = head;
    fail_read_address = head + offset_fileptr; fail_read_remaining = 1;
    assert(trustcache_file_upload(file) == EIO && head == oldHead && !free_calls);
    fail_buf_write_address = head + ksizeof(trustcache);
    assert(trustcache_file_upload(file) == EIO && head == oldHead && !free_calls);
    fail_buf_write_address = 0;
    trustcache_file_v1 *replacement = make_file(2);
    memcpy(replacement->uuid, file->uuid, sizeof(uuid_t));
    write64_calls = 0; fail_write64_call = 1;
    assert(trustcache_file_upload(replacement) == EIO && head == oldHead && !free_calls);
    reset(); assert(trustcache_file_upload(file) == 0);
    oldHead = head;
    _trustcache_file_init(replacement);
    replacement->length = 2;
    write64_calls = 0;
    fail_write64_call = 6; commit_failed_write64_call = 6;
    fail_write64_call_2 = 7;
    assert(trustcache_file_upload(replacement) == EIO);
    assert(head != oldHead && !free_calls && resolve(head, JB_TRUSTCACHE_SIZE));
    assert(kread64(head + offset_nextptr) == oldHead);
    assert(kread64(oldHead + offset_prevptr) == head);
    free(file); free(replacement);
}

// 运行跨页与故障回归，不依赖真实设备或内核。
int main(void)
{
    test_batch(JB_TRUSTCACHE_ENTRY_COUNT-2, 5);
    test_batch(0, JB_TRUSTCACHE_ENTRY_COUNT*3+17);
    test_batch(0, JB_TRUSTCACHE_ENTRY_COUNT*64+17);
    test_hash_wrapper();
    test_input_edges();
    test_alloc_failures();
    test_link_failures();
    test_io_failures();
    test_partial_failure();
    test_link_read_failures();
    test_indirect_root_failures();
    test_tail_read_failure();
    test_head_insert_rollback();
    test_rollback_failures();
    test_tail_insert_rollback();
    test_remove_failures();
    test_file_upload_failures();
    puts("PASS: TrustCache partial page, multi-page, bounded memory, wrappers, empty/single, allocation/link/I/O failures, checked traversal, conditional rollback, upload failures");
    return 0;
}
"""


def without_includes(text):
    return "\n".join(line for line in text.splitlines() if not line.startswith("#include"))


def extract_functions(source_text):
    code = source_text.split("\n/*int jb_trustcache_add_file(", 1)[0]
    upload = source_text.split("int trustcache_file_upload(trustcache_file_v1 *tc)", 1)[1]
    upload = "int trustcache_file_upload(trustcache_file_v1 *tc)" + upload.split("int trustcache_file_upload_with_uuid(", 1)[0]
    return without_includes(code + "\n" + upload)


def no_core_dump():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-regression", action="store_true",
                        help="另外恢复旧输入偏移错误，验证测试确实拒绝该缺陷")
    parser.add_argument("--check-previous-revision", metavar="REV",
                        help="读取指定 Git 版本，证明尾部读取和头插回滚测试会拒绝修复前实现")
    args = parser.parse_args()
    code = extract_functions(SOURCE.read_text())
    structs = without_includes(STRUCTS.read_text())
    environment = os.environ.copy()
    environment["ASAN_OPTIONS"] = f"detect_leaks={int(sys.platform != 'darwin')}:abort_on_error=1"
    cases = [("current", code, TESTS, None)]
    if args.check_regression:
        needle = "entries[consumedEntryCount+i]"
        assert needle in code, "被测输入偏移表达式已改变，请更新回归变异点"
        cases.append(("original input-offset defect", code.replace(needle, "entries[i]", 1),
                      TESTS, "key < expected && !seen[key]"))
    if args.check_previous_revision:
        previous_text = subprocess.run(
            ["git", "show", f"{args.check_previous_revision}:{SOURCE.relative_to(ROOT)}"],
            check=True, cwd=ROOT, capture_output=True, text=True).stdout
        previous_code = extract_functions(previous_text)
        for test_name, expected in [
            ("test_tail_read_failure", "_jb_trustcache_grow(&added) == EIO"),
            ("test_head_insert_rollback", "prev == previous"),
        ]:
            tests = TESTS.split("int main(void)", 1)[0] + f"int main(void) {{ {test_name}(); return 0; }}\n"
            cases.append((f"{args.check_previous_revision} {test_name}", previous_code, tests, expected))
    with tempfile.TemporaryDirectory(prefix="trustcache-regression-", dir=ROOT / "worker") as tmp:
        tmp_path = Path(tmp)
        for name, actual, tests, expected_failure in cases:
            source = tmp_path / "trustcache_regression.c"
            binary = tmp_path / "trustcache_regression"
            source.write_text(PRELUDE + structs + STUBS + actual + tests)
            subprocess.run(["clang", "-std=gnu11", "-fblocks", "-g", "-O1",
                            "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                            "-Werror", "-Wno-gnu-variable-sized-type-not-at-end",
                            "-Wno-unused-parameter", "-Wno-unused-function",
                            str(source), "-o", str(binary)], check=True, cwd=ROOT)
            result = subprocess.run([str(binary)], env=environment, cwd=ROOT,
                                    capture_output=True, text=True, preexec_fn=no_core_dump)
            if expected_failure:
                if result.returncode == 0:
                    raise SystemExit(f"FAIL: 回归测试未拒绝 {name}")
                if expected_failure not in result.stderr:
                    raise SystemExit(f"FAIL: {name} 因非预期原因退出\n" + result.stderr)
                print(f"PASS: {name} is rejected")
            else:
                print(result.stdout, end="")
                if result.returncode:
                    raise SystemExit(result.stderr or f"测试失败: {result.returncode}")


if __name__ == "__main__":
    main()
