#include "trustcache.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include "kernel.h"
#include "info.h"
#include "primitives.h"

void _trustcache_file_init(trustcache_file_v1 *file)
{
	memset(file, 0, sizeof(*file));
	file->version = 1;
	uuid_generate(file->uuid);
}

// iOS 16:
// ppl_trust_cache_rt has trustcache runtime
// **(ppl_trust_cache_rt+0x20) seems to have the loaded trustcache linked list
// trustcache struct changed, "next" is still at +0x0, but "this" is at +0x20

// 获取保存链表头的地址，区分读取失败与空链表。
static int _trustcache_list_get_start_address(uint64_t *addressOut)
{
	*addressOut = 0;
	if (ksymbol(pmap_image4_trust_caches)) {
		*addressOut = ksymbol(pmap_image4_trust_caches);
		return 0;
	}
	uint64_t runtime = ksymbol(ppl_trust_cache_rt);
	if (!runtime) runtime = ksymbol_txm(txm_trustcache_root);
	if (!runtime) return ENOTSUP;
	int r = kreadbuf(runtime + 0x20, addressOut, sizeof(*addressOut));
	if (r != 0) return r;
	return *addressOut ? 0 : EFAULT;
}

// 读取链表头，失败时不返回可被误认为空链表的地址。
static int _trustcache_list_get_start(uint64_t *startOut)
{
	*startOut = 0;
	uint64_t address = 0;
	int r = _trustcache_list_get_start_address(&address);
	if (r != 0) return r;
	return kreadbuf(address, startOut, sizeof(*startOut));
}

// 遍历链表并传递根指针及后继指针的读取错误。
static int _trustcache_list_enumerate(void (^enumerateBlock)(uint64_t tcKaddr, bool *stop))
{
	uint64_t curTC = 0;
	int r = _trustcache_list_get_start(&curTC);
	if (r != 0) return r;
	while (curTC != 0) {
		bool stop = false;
		enumerateBlock(curTC, &stop);
		if (stop) break;
		r = kreadbuf(curTC + koffsetof(trustcache, nextptr), &curTC, sizeof(curTC));
		if (r != 0) return r;
	}
	return 0;
}

// 仅恢复仍为本次写入值的指针，避免覆盖其他调用方已经推进的链表。
static int _trustcache_restore_pointer(uint64_t address, uint64_t originalValue, uint64_t writtenValue)
{
	uint64_t currentValue = 0;
	int r = kreadbuf(address, &currentValue, sizeof(currentValue));
	if (r != 0) return r;
	if (currentValue == originalValue) return 0;
	if (currentValue != writtenValue) return EBUSY;
	return kwrite64(address, originalValue);
}

// 插入已初始化的缓存；失败时调用方必须保留可能仍被引用的内存。
int trustcache_list_insert(uint64_t tcToInsert)
{
	if (!tcToInsert) return EINVAL;

	if (ksymbol(SPTMArgs)) {
		// TXM 只能写自身分配的页，因此始终在原生链表尾部追加。
		__block uint64_t lastTC = 0;
		int r = _trustcache_list_enumerate(^(uint64_t tcKaddr, bool *stop) {
			lastTC = tcKaddr;
		});
		if (r != 0) return r;
		if (!lastTC) return ENOENT;

		if (koffsetof(trustcache, prevptr)) {
			r = kwrite64(tcToInsert + koffsetof(trustcache, prevptr), lastTC);
			if (r != 0) return r;
		}
		uint64_t nextAddress = lastTC + koffsetof(trustcache, nextptr);
		r = kwrite64(nextAddress, tcToInsert);
		if (r != 0) {
			int rollbackResult = _trustcache_restore_pointer(nextAddress, 0, tcToInsert);
			return rollbackResult != 0 ? rollbackResult : r;
		}
		return 0;
	}

	uint64_t startAddress = 0, previousStartTC = 0, previousPrev = 0;
	int r = _trustcache_list_get_start_address(&startAddress);
	if (r != 0) return r;
	r = kreadbuf(startAddress, &previousStartTC, sizeof(previousStartTC));
	if (r != 0) return r;
	uint64_t previousPrevAddress = previousStartTC && koffsetof(trustcache, prevptr)
		? previousStartTC + koffsetof(trustcache, prevptr) : 0;
	if (previousPrevAddress) {
		r = kreadbuf(previousPrevAddress, &previousPrev, sizeof(previousPrev));
		if (r != 0) return r;
	}
	r = kwrite64(tcToInsert + koffsetof(trustcache, nextptr), previousStartTC);
	if (r != 0) return r;
	if (previousPrevAddress) {
		r = kwrite64(previousPrevAddress, tcToInsert);
		if (r != 0) {
			int rollbackResult = _trustcache_restore_pointer(previousPrevAddress, previousPrev, tcToInsert);
			return rollbackResult != 0 ? rollbackResult : r;
		}
	}
	r = kwrite64(startAddress, tcToInsert);
	if (r != 0) {
		// 写入失败也可能已生效；先恢复根，再恢复旧头的反向链接。
		int rollbackResult = _trustcache_restore_pointer(startAddress, previousStartTC, tcToInsert);
		if (rollbackResult != 0) return rollbackResult;
		if (previousPrevAddress) {
			rollbackResult = _trustcache_restore_pointer(previousPrevAddress, previousPrev, tcToInsert);
			if (rollbackResult != 0) return rollbackResult;
		}
	}
	return r;
}

// 摘除缓存并检查每次读写，失败时回滚且禁止调用方释放该页。
int trustcache_list_remove(uint64_t tcKaddr)
{
	if (!tcKaddr) return EINVAL;
	uint64_t startAddress = 0, curTc = 0;
	int r = _trustcache_list_get_start_address(&startAddress);
	if (r != 0) return r;
	r = kreadbuf(startAddress, &curTc, sizeof(curTc));
	if (r != 0) return r;

	uint64_t previousAddress = startAddress;
	uint64_t previousTc = 0;
	while (curTc && curTc != tcKaddr) {
		previousTc = curTc;
		previousAddress = curTc + koffsetof(trustcache, nextptr);
		r = kreadbuf(previousAddress, &curTc, sizeof(curTc));
		if (r != 0) return r;
	}
	if (!curTc) return ENOENT;

	uint64_t nextTc = 0, nextPrev = 0;
	r = kreadbuf(tcKaddr + koffsetof(trustcache, nextptr), &nextTc, sizeof(nextTc));
	if (r != 0) return r;
	uint64_t nextPrevAddress = nextTc && koffsetof(trustcache, prevptr)
		? nextTc + koffsetof(trustcache, prevptr) : 0;
	if (nextPrevAddress) {
		r = kreadbuf(nextPrevAddress, &nextPrev, sizeof(nextPrev));
		if (r != 0) return r;
	}
	r = kwrite64(previousAddress, nextTc);
	if (r != 0) {
		int rollbackResult = _trustcache_restore_pointer(previousAddress, tcKaddr, nextTc);
		return rollbackResult != 0 ? rollbackResult : r;
	}
	if (nextPrevAddress) {
		r = kwrite64(nextPrevAddress, previousTc);
		if (r != 0) {
			int rollbackResult = _trustcache_restore_pointer(nextPrevAddress, nextPrev, previousTc);
			int forwardResult = _trustcache_restore_pointer(previousAddress, tcKaddr, nextTc);
			if (forwardResult != 0) return forwardResult;
			if (rollbackResult != 0) return rollbackResult;
		}
	}
	return r;
}

int _trustcache_file_sort_entry_comparator_v1(const void * vp1, const void * vp2)
{
	trustcache_entry_v1* tc1 = (trustcache_entry_v1*)vp1;
	trustcache_entry_v1* tc2 = (trustcache_entry_v1*)vp2;
	return memcmp(tc1->hash, tc2->hash, sizeof(cdhash_t));
}

void _trustcache_file_sort(trustcache_file_v1 *file)
{
	qsort(file->entries, file->length, sizeof(trustcache_entry_v1), _trustcache_file_sort_entry_comparator_v1);
}

// 检查页内文件指针和标记，读取失败时不把该页误判为普通缓存。
static int _is_jb_trustcache(uint64_t tcKaddr, bool *isJbOut)
{
	*isJbOut = false;
	uint64_t file = 0;
	int r = kreadbuf(tcKaddr + koffsetof(trustcache, fileptr), &file, sizeof(file));
	if (r != 0) return r;
	if (file == tcKaddr + offsetof(jb_trustcache, file)) {
		uint64_t magic = 0;
		r = kreadbuf(tcKaddr + offsetof(jb_trustcache, magic), &magic, sizeof(magic));
		if (r != 0) return r;
		*isJbOut = magic == JB_MAGIC;
	}
	return 0;
}

// 遍历越狱缓存，并向修改操作传递链表及页识别错误。
static int _jb_trustcache_enumerate(void (^enumerateBlock)(uint64_t jbTcKaddr, bool *stop))
{
	__block int identifyResult = 0;
	int r = _trustcache_list_enumerate(^(uint64_t tcKaddr, bool *stop) {
		bool isJb = false;
		identifyResult = _is_jb_trustcache(tcKaddr, &isJb);
		if (identifyResult != 0) {
			*stop = true;
			return;
		}
		if (isJb) enumerateBlock(tcKaddr, stop);
	});
	return r != 0 ? r : identifyResult;
}

void jb_trustcache_clear(void)
{
	_jb_trustcache_enumerate(^(uint64_t jbTcKaddr, bool *stop) {
		kwrite64(jbTcKaddr + offsetof(jb_trustcache, file.length), 0);
	});
}

// 分配并初始化新缓存页，失败时不发布无效地址。
static int _jb_trustcache_grow(uint64_t *jbTcKernOut)
{
	*jbTcKernOut = 0;
	uint64_t jbTcKern = 0;
	int r = kalloc(&jbTcKern, JB_TRUSTCACHE_SIZE);
	if (r != 0) return r;
	if (!jbTcKern) return ENOMEM;

	jb_trustcache header = {0};
	jb_trustcache *jbTc = &header;
	_trustcache_file_init(&jbTc->file);
	jbTc->magic = JB_MAGIC;
	*(uint64_t *)(jbTc->trustcache + koffsetof(trustcache, fileptr)) = (jbTcKern + offsetof(jb_trustcache, file));
	if (koffsetof(trustcache, size)) {
		*(uint64_t *)(jbTc->trustcache + koffsetof(trustcache, size)) = JB_TRUSTCACHE_SIZE;
	}
	if (koffsetof(trustcache, type)) {
		*(uint64_t *)(jbTc->trustcache + koffsetof(trustcache, type)) = 0x5;
	}
	r = kwritebuf(jbTcKern, jbTc, sizeof(*jbTc));
	if (r != 0) {
		kfree(jbTcKern, JB_TRUSTCACHE_SIZE);
		return r;
	}
	r = trustcache_list_insert(jbTcKern);
	// 插链失败可能已有部分写入，保留该页，避免释放仍被引用的内存。
	if (r != 0) return r;
	*jbTcKernOut = jbTcKern;
	return 0;
}

// 按已消费输入跨页追加条目，整个批次复用一个固定大小缓冲区。
int jb_trustcache_add_entries(struct trustcache_entry_v1 *entries, uint32_t entryCount)
{
	if (entryCount == 0) return 0;
	if (!entries) return EINVAL;
	jb_trustcache *jbTc = malloc(JB_TRUSTCACHE_SIZE);
	if (!jbTc) return ENOMEM;
	__block int r = 0;
	uint32_t consumedEntryCount = 0;
	while (consumedEntryCount < entryCount) {
		__block uint64_t freeJbTcKaddr = 0;
		__block uint32_t freeJbTcCurrentLength = 0;
		int enumerateResult = _jb_trustcache_enumerate(^(uint64_t jbTcKaddr, bool *stop) {
			uint32_t length = 0;
			r = kreadbuf(jbTcKaddr + offsetof(jb_trustcache, file.length), &length, sizeof(length));
			if (r != 0 || length > JB_TRUSTCACHE_ENTRY_COUNT) {
				if (r == 0) r = EINVAL;
				*stop = true;
				return;
			}
			if (length < JB_TRUSTCACHE_ENTRY_COUNT) {
				freeJbTcKaddr = jbTcKaddr;
				freeJbTcCurrentLength = length;
				*stop = true;
			}
		});
		if (enumerateResult != 0) r = enumerateResult;
		if (r != 0) break;
		if (freeJbTcKaddr == 0) {
			r = _jb_trustcache_grow(&freeJbTcKaddr);
			if (r != 0) break;
		}

		r = kreadbuf(freeJbTcKaddr, jbTc, JB_TRUSTCACHE_SIZE);
		if (r != 0) break;
		if (jbTc->file.length != freeJbTcCurrentLength) {
			r = EBUSY;
			break;
		}
		uint32_t remainingEntryCount = entryCount - consumedEntryCount;
		uint32_t entryCountToInsert = JB_TRUSTCACHE_ENTRY_COUNT - freeJbTcCurrentLength;
		if (remainingEntryCount < entryCountToInsert) {
			entryCountToInsert = remainingEntryCount;
		}

		for (uint32_t i = 0; i < entryCountToInsert; i++) {
			jbTc->file.entries[freeJbTcCurrentLength+i] = entries[consumedEntryCount+i];
		}
		jbTc->file.length += entryCountToInsert;
		_trustcache_file_sort(&jbTc->file);
		r = kwritebuf(freeJbTcKaddr, jbTc, JB_TRUSTCACHE_SIZE);
		if (r != 0) break;
		consumedEntryCount += entryCountToInsert;
	}
	free(jbTc);
	return r;
}

// 分块转换散列，避免批次大小决定栈空间，并传递追加失败。
int jb_trustcache_add_cdhashes(cdhash_t *hashes, uint32_t hashCount)
{
	if (hashCount == 0) return 0;
	if (!hashes) return EINVAL;
	struct trustcache_entry_v1 entries[JB_TRUSTCACHE_ENTRY_COUNT];
	uint32_t consumedHashCount = 0;
	while (consumedHashCount < hashCount) {
		uint32_t count = hashCount - consumedHashCount;
		if (count > JB_TRUSTCACHE_ENTRY_COUNT) count = JB_TRUSTCACHE_ENTRY_COUNT;
		for (uint32_t i = 0; i < count; i++) {
			memcpy(entries[i].hash, hashes[consumedHashCount+i], sizeof(cdhash_t));
			entries[i].hash_type = 1;
			entries[i].flags = 0;
		}
		int r = jb_trustcache_add_entries(entries, count);
		if (r != 0) return r;
		consumedHashCount += count;
	}
	return 0;
}

// 通过批量入口追加单条记录。
int jb_trustcache_add_entry(struct trustcache_entry_v1 entry)
{
	return jb_trustcache_add_entries(&entry, 1);
}


/*int jb_trustcache_add_file(const char *filePath)
{
	
}

int jb_trustcache_add_directory(const char *directoryPath)
{

}*/

xpc_object_t jb_trustcache_info(void)
{
	xpc_object_t arr = xpc_array_create_empty();
	_jb_trustcache_enumerate(^(uint64_t jbTcKaddr, bool *stop) {
		uuid_t uuid;
		kreadbuf(jbTcKaddr + offsetof(jb_trustcache, file.uuid), (void *)uuid, sizeof(uuid));
		uint32_t length = kread32(jbTcKaddr + offsetof(jb_trustcache, file.length));

		xpc_object_t tcDict = xpc_dictionary_create_empty();
		xpc_dictionary_set_data(tcDict, "uuid", &uuid, sizeof(uuid));

		xpc_object_t hashesArr = xpc_array_create_empty();
		for (int i = 0; i < length; i++) {
			trustcache_entry_v1 entry;
			kreadbuf(jbTcKaddr + offsetof(jb_trustcache, file.entries[i]), &entry, sizeof(entry));
			xpc_array_set_data(hashesArr, XPC_ARRAY_APPEND, &entry.hash, sizeof(entry.hash));
		}
		xpc_dictionary_set_value(tcDict, "cdhashes", hashesArr);
		xpc_release(hashesArr);

		xpc_array_append_value(arr, tcDict);
		xpc_release(tcDict);
	});
	return arr;
}

void jb_trustcache_debug_print(FILE *f)
{
	__block int i = 0;
	_jb_trustcache_enumerate(^(uint64_t jbTcKaddr, bool *stop) {
		uuid_t uuid;
		kreadbuf(jbTcKaddr + offsetof(jb_trustcache, file.uuid), (void *)uuid, sizeof(uuid));
		uint32_t length = kread32(jbTcKaddr + offsetof(jb_trustcache, file.length));

		uint32_t *uuidData = (uint32_t *)uuid;
		fprintf(f, "Jailbreak TrustCache %d <%08x%08x%08x%08x> (length: %u) (kaddr: 0x%llx):\n", i++, htonl(uuidData[0]), htonl(uuidData[1]), htonl(uuidData[2]), htonl(uuidData[3]), length, jbTcKaddr);
		
		for (uint32_t j = 0; j < length; j++) {
			trustcache_entry_v1 entry;
			kreadbuf(jbTcKaddr + offsetof(jb_trustcache, file.entries[j]), &entry, sizeof(entry));
			fprintf(f, "| ");
			for (uint32_t k = 0; k < sizeof(cdhash_t); k++) {
				fprintf(f, "%02x", entry.hash[k]);
			}
			fprintf(f, "\n");
		}
	});


	/////////////////////////////////////////////////////////////////
	_trustcache_list_enumerate(^(uint64_t tcKaddr, bool *stop) {
		bool isJb = false;
		if (_is_jb_trustcache(tcKaddr, &isJb) != 0) { *stop = true; return; }
		if (isJb) return;

		uint64_t tcFileKaddr = kread64(tcKaddr + koffsetof(trustcache, fileptr));
		uint32_t length = kread32(tcFileKaddr + offsetof(trustcache_file_v1, length));
		if (length == 0) return;
	
		uuid_t uuid;
		kreadbuf(tcFileKaddr + offsetof(trustcache_file_v1, uuid), (void *)uuid, sizeof(uuid));

		uint32_t *uuidData = (uint32_t *)uuid;
		fprintf(f, "TrustCache File <%08x%08x%08x%08x> (length: %u) (kaddr: 0x%llx):\n", htonl(uuidData[0]), htonl(uuidData[1]), htonl(uuidData[2]), htonl(uuidData[3]), length, tcFileKaddr);
		
		for (uint32_t j = 0; j < length; j++) {
			trustcache_entry_v1 entry;
			kreadbuf(tcFileKaddr + offsetof(trustcache_file_v1, entries[j]), &entry, sizeof(entry));
			fprintf(f, "| ");
			for (uint32_t k = 0; k < sizeof(cdhash_t); k++) {
				fprintf(f, "%02x", entry.hash[k]);
			}
			fprintf(f, "\n");
		}
	});
	
}

// 上传独立缓存文件，任何读取、初始化或插链失败均传递给调用方。
int trustcache_file_upload(trustcache_file_v1 *tc)
{
	if (!tc) return EINVAL;
	uint64_t tcSize = ksizeof(trustcache) + sizeof(trustcache_file_v1) + (tc->length * sizeof(trustcache_entry_v1));
	if (tcSize > JB_TRUSTCACHE_SIZE) return EINVAL;

	__block uint64_t existingTcKaddr = 0;
	__block int lookupResult = 0;
	int r = _trustcache_list_enumerate(^(uint64_t tcKaddr, bool *stop) {
		uint64_t tcFileKaddr = 0;
		lookupResult = kreadbuf(tcKaddr + koffsetof(trustcache, fileptr), &tcFileKaddr, sizeof(tcFileKaddr));
		if (lookupResult == 0 && !tcFileKaddr) lookupResult = EFAULT;
		uuid_t tcFileUUID;
		if (lookupResult == 0) {
			lookupResult = kreadbuf(tcFileKaddr + offsetof(trustcache_file_v1, uuid), tcFileUUID, sizeof(tcFileUUID));
		}
		if (lookupResult != 0) {
			*stop = true;
			return;
		}
		if (memcmp(tcFileUUID, tc->uuid, sizeof(tcFileUUID)) == 0) {
			existingTcKaddr = tcKaddr;
			*stop = true;
		}
	});
	if (r != 0) return r;
	if (lookupResult != 0) return lookupResult;

	if (existingTcKaddr != 0) {
		bool isJb = false;
		r = _is_jb_trustcache(existingTcKaddr, &isJb);
		if (r != 0) return r;
		if (isJb) return EINVAL;

		uint64_t prevTcFile = 0;
		uint32_t prevTcLength = 0;
		r = kreadbuf(existingTcKaddr + koffsetof(trustcache, fileptr), &prevTcFile, sizeof(prevTcFile));
		if (r != 0) return r;
		r = kreadbuf(prevTcFile + offsetof(trustcache_file_v1, length), &prevTcLength, sizeof(prevTcLength));
		if (r != 0) return r;
		uint64_t prevTcSize = ksizeof(trustcache) + sizeof(trustcache_file_v1) + (prevTcLength * sizeof(trustcache_entry_v1));
		if (prevTcSize == tcSize) {
			return kwritebuf(prevTcFile, tc, tcSize - ksizeof(trustcache));
		}

		// 仅在确认摘链成功后释放；失败时保留仍可能被引用的旧页。
		r = trustcache_list_remove(existingTcKaddr);
		if (r != 0) return r;
		usleep(10000);
		kfree(existingTcKaddr, prevTcSize);
	}

	uint64_t tcKaddr = 0;
	r = kalloc(&tcKaddr, tcSize);
	if (r != 0) return r;
	if (!tcKaddr) return ENOMEM;

	char nullBuf[ksizeof(trustcache)];
	memset(nullBuf, 0, sizeof(nullBuf));
	r = kwritebuf(tcKaddr, nullBuf, sizeof(nullBuf));
	uint64_t tcFileKaddr = tcKaddr + ksizeof(trustcache);
	if (r == 0) r = kwritebuf(tcFileKaddr, tc, tcSize - ksizeof(trustcache));
	if (r == 0) r = kwrite64(tcKaddr + koffsetof(trustcache, fileptr), tcFileKaddr);
	if (r == 0 && koffsetof(trustcache, size)) {
		r = kwrite64(tcKaddr + koffsetof(trustcache, size), tcSize);
	}
	if (r == 0 && koffsetof(trustcache, type)) {
		r = kwrite64(tcKaddr + koffsetof(trustcache, type), 0x5);
	}
	if (r != 0) {
		kfree(tcKaddr, tcSize);
		return r;
	}

	// 插链失败可能包含回滚失败，不能据此释放新页。
	return trustcache_list_insert(tcKaddr);
}

int trustcache_file_upload_with_uuid(trustcache_file_v1 *tc, uuid_t uuid)
{
	memcpy(tc->uuid, uuid, sizeof(uuid_t));
	return trustcache_file_upload(tc);
}

int trustcache_file_build_from_cdhashes(cdhash_t *CDHashes, uint32_t CDHashCount, trustcache_file_v1 **tcOut)
{
	if (!CDHashes || CDHashCount == 0 || !tcOut) return -1;

	size_t tcSize = sizeof(trustcache_file_v1) + (sizeof(trustcache_entry_v1) * CDHashCount);
	trustcache_file_v1 *file = malloc(tcSize);
	_trustcache_file_init(file);

	file->length = CDHashCount;
	for (uint32_t i = 0; i < CDHashCount; i++) {
		memcpy(file->entries[i].hash, CDHashes[i], sizeof(cdhash_t));
		file->entries[i].hash_type = 2;
		file->entries[i].flags = 0;
	}
	_trustcache_file_sort(file);

	*tcOut = file;
	return 0;
}

int trustcache_file_build_from_path(const char *filePath, trustcache_file_v1 **tcOut)
{
	int fd = open(filePath, O_RDONLY);
	struct stat s = { 0 };
	fstat(fd, &s);
	
	size_t tcSize = s.st_size;
	if (tcSize < (sizeof(trustcache_file_v1))) {
		// To small to be a TrustCache, file is probably malformed
		return -1;
	}

	trustcache_file_v1 *file = malloc(tcSize);
	read(fd, file, tcSize);
	close(fd);

	size_t actualTcSize = sizeof(trustcache_file_v1) + (sizeof(trustcache_entry_v1) * file->length);
	if (actualTcSize != tcSize) {
		// Size mismatch, file is malformed
		free(file);
		return -1;
	}

	*tcOut = file;
	return 0;
}

bool trustcache_contains_cdhash(uint64_t tcKaddr, cdhash_t CDHash)
{
	uint64_t tcFileKaddr = kread64(tcKaddr + koffsetof(trustcache, fileptr));
	uint32_t length = kread32(tcFileKaddr + offsetof(trustcache_file_v1, length));
	if (length == 0) return false;

	int32_t left = 0;
	int32_t right = length - 1;

	while (left <= right) {
		int32_t mid = (left + right) / 2;
		cdhash_t itCDHash;
		kreadbuf(tcFileKaddr + offsetof(trustcache_file_v1, entries[mid].hash), itCDHash, CS_CDHASH_LEN);
		int32_t cmp = memcmp(CDHash, itCDHash, CS_CDHASH_LEN);
		if (cmp == 0) {
			return true;
		}
		if (cmp < 0) {
			right = mid - 1;
		} else {
			left = mid + 1;
		}
	}
	return false;
}

bool is_cdhash_trustcached(cdhash_t CDHash)
{
	__block bool inTrustCache = false;
	_trustcache_list_enumerate(^(uint64_t tcKaddr, bool *stop) {
		bool inThisTrustCache = trustcache_contains_cdhash(tcKaddr, CDHash);
		if (inThisTrustCache) {
			inTrustCache = true;
			*stop = true;
		}
	});
	return inTrustCache;
}
