#include <libgen.h>
#include <sys/stat.h>
#include <mach-o/dyld.h>

#include <choma/Fat.h>
#include <choma/MachO.h>
#include <choma/Host.h>
#include <choma/MachOByteOrder.h>
#include <choma/CodeDirectory.h>

#include <libjailbreak/libjailbreak.h>
#include <libjailbreak/codesign.h>
#include "common.h"
#include "log.h"

extern MachO* fat_find_preferred_slice(Fat* fat);

extern CS_DecodedBlob *csd_superblob_find_best_code_directory(CS_DecodedSuperBlob *decodedSuperblob);
extern bool code_directory_calculate_page_hash(CS_CodeDirectory *codeDir, MachO *macho, int slot, uint8_t *pageHashOut);
extern bool csd_superblob_is_adhoc_signed(CS_DecodedSuperBlob *superblob);

/* 
if here are any unclosed file descriptors before the Dopamine process ends, 
	the "attempt to map verified executable page" panic may occur.
*/
// 以可写方式解析文件，解析失败时释放尚未移交所有权的流。
Fat* fat_init_for_writing(const char *filePath)
{
	//make sure the file already exists, otherwise choma will create a new file
	if(access(filePath, W_OK) != 0) {
		JBLogError("Error: file is not writable: %s\n", filePath);
		return NULL;
	}

    MemoryStream *stream = file_stream_init_from_path(filePath, 0, FILE_STREAM_SIZE_AUTO, FILE_STREAM_FLAG_WRITABLE);
    if(!stream) return NULL;

	Fat *fat = fat_init_from_memory_stream(stream);
	if (!fat) memory_stream_free(stream);
	return fat;
}

// 计算代码目录散列并截取 cdhash。
int calc_cdhash(uint8_t *cdBlob, size_t cdBlobSize, uint8_t hashtype, void *cdhashOut)
{
    // Longest possible buffer, will cut it off at the end as cdhash size is fixed
    uint8_t cdhash[CC_SHA384_DIGEST_LENGTH];

    JBLogDebug("head=%llx  %lx\n", *(uint64_t*)cdBlob, cdBlobSize);

    switch (hashtype) {
		case CS_HASHTYPE_SHA160_160: {
			CC_SHA1(cdBlob, (CC_LONG)cdBlobSize, cdhash);
			break;
		}
		
		case CS_HASHTYPE_SHA256_256:
		case CS_HASHTYPE_SHA256_160: {
			CC_SHA256(cdBlob, (CC_LONG)cdBlobSize, cdhash);
			break;
		}

		case CS_HASHTYPE_SHA384_384: {
			CC_SHA384(cdBlob, (CC_LONG)cdBlobSize, cdhash);
			break;
		}

        default:
        return -1;
	}

    memcpy(cdhashOut, cdhash, CS_CDHASH_LEN);
    return 0;
}

// 按文件偏移定位待处理切片。
MachO* fat_find_slice_by_offset(Fat* fat, uint64_t offset)
{
	__block MachO* result = NULL;
	fat_enumerate_slices(fat, ^(MachO *macho, bool *stop) {
		if(macho->archDescriptor.offset == offset) {
			result = macho;
			*stop = true;
		}
	});
	return result;
}

// 处理宿主首选切片。
int ensure_randomized_cdhash(const char* inputPath, void* cdhashOut)
{
	return ensure_randomized_cdhash_for_slice(inputPath, -1, cdhashOut);
}

// 在内存中覆盖首节标记并计算首个代码页散列，校验失败不修改原文件。
static int recdhash_prepare_page_hash(MachO *macho, const CS_CodeDirectory *directory,
	uint64_t sectionOffset, const struct section_64 *section, uint8_t hash[CC_SHA384_DIGEST_LENGTH])
{
	size_t expectedHashSize;
	switch (directory->hashType) {
		case CS_HASHTYPE_SHA160_160: expectedHashSize = CC_SHA1_DIGEST_LENGTH; break;
		case CS_HASHTYPE_SHA256_160: expectedHashSize = CS_CDHASH_LEN; break;
		case CS_HASHTYPE_SHA256_256: expectedHashSize = CC_SHA256_DIGEST_LENGTH; break;
		case CS_HASHTYPE_SHA384_384: expectedHashSize = CC_SHA384_DIGEST_LENGTH; break;
		default: return -1;
	}
	if (directory->hashSize != expectedHashSize || directory->pageSize > 30 ||
		!directory->nCodeSlots || !directory->codeLimit) return -1;
	uint64_t pageSize = directory->pageSize ? (1ULL << directory->pageSize) : directory->codeLimit;
	if (pageSize > directory->codeLimit) pageSize = directory->codeLimit;
	if (pageSize > memory_stream_get_size(macho->stream) || sectionOffset > pageSize ||
		sizeof(*section) > pageSize - sectionOffset) return -1;
	uint8_t *page = malloc((size_t)pageSize);
	if (!page) return -1;
	if (macho_read_at_offset(macho, 0, (size_t)pageSize, page) != 0) { free(page); return -1; }
	memcpy(page + sectionOffset, section, sizeof(*section));
	switch (directory->hashType) {
		case CS_HASHTYPE_SHA160_160: CC_SHA1(page, (CC_LONG)pageSize, hash); break;
		case CS_HASHTYPE_SHA256_160:
		case CS_HASHTYPE_SHA256_256: CC_SHA256(page, (CC_LONG)pageSize, hash); break;
		case CS_HASHTYPE_SHA384_384: CC_SHA384(page, (CC_LONG)pageSize, hash); break;
	}
	free(page);
	return 0;
}

/* on ios16(+?)
1: if an executable has process(es) running it, after opening it with open(O_RDWR), 
		it can no longer be executed (EBADMACHO) until the previous process(es) exits.
2: if an executable is opened with O_RDWR, 
	it cannot be executed until the file descriptor is closed.
3: `open(O_RDWR)` on certain binaries(e.g., WebContent) may cause deadlock (krwlock for writing)
	while `read`/`posix_spawn` happen to be running on the binary.
*/
// 先准备新签名，再写入并在失败时恢复；重试仍验证标记对应的真实页散列。
int ensure_randomized_cdhash_for_slice(const char* inputPath, uint64_t offset, void* cdhashOut)
{
	JBLogDebug("ensure_randomized_cdhash_for_slice(slice=%llx): %s\n", offset, inputPath);

	struct stat orig_st;
	if(stat(inputPath, &orig_st) != 0) {
		return -1;
	}

    Fat* fat = fat_init_for_writing(inputPath);
    if (!fat) {
		JBLogError("Error: failed to init fat: %s\n", inputPath);
		return -1;
	}

    MachO *macho = (offset==-1) ? fat_find_preferred_slice(fat) : fat_find_slice_by_offset(fat, offset);
	if(!macho) {
		JBLogError("Error: failed to find preferred slice: %s\n", inputPath);
		fat_free(fat);
		return -1;
	}

	__block int foundCount = 0;
    __block uint64_t textsegoffset = 0;
    __block uint64_t firstsectoffset = 0;
	__block struct section_64 firstsection={0};
    __block struct segment_command_64 textsegment={0};
    __block struct linkedit_data_command linkedit={0};

    int parseResult = macho_enumerate_load_commands(macho, ^(struct load_command loadCommand, uint64_t offset, void *cmd, bool *stop) {
		bool foundOne = false;
		if (loadCommand.cmd == LC_SEGMENT_64) {
			struct segment_command_64 *segmentCommand = ((struct segment_command_64 *)cmd);

			if (strncmp(segmentCommand->segname, "__TEXT", sizeof(segmentCommand->segname)) != 0) return;

			textsegoffset = offset;
			textsegment = *segmentCommand;

			if(segmentCommand->nsects==0) {
				*stop=true;
				return;
			}

			firstsectoffset = textsegoffset + sizeof(*segmentCommand);
			firstsection = *(struct section_64*)((uint64_t)segmentCommand + sizeof(*segmentCommand));
			if (strncmp(firstsection.segname, "__TEXT", sizeof(firstsection.segname)) != 0) {
				*stop=true;
				return;
			}
			
			*stop = foundOne;
			foundOne = true;
			foundCount++;
		}
		if (loadCommand.cmd == LC_CODE_SIGNATURE) {
			struct linkedit_data_command *csLoadCommand = ((struct linkedit_data_command *)cmd);
			JBLogDebug("LC_CODE_SIGNATURE: %x\n", csLoadCommand->dataoff);

			linkedit = *csLoadCommand;

			*stop = foundOne;
			foundOne = true;
			foundCount++;
		}
    });

    if(parseResult != 0 || foundCount != 2) {
		JBLogError("Error: failed to parse macho file: %s\n", inputPath);
		fat_free(fat);
		return -1;
	}

    uint64_t* rd = (uint64_t*)&(textsegment.segname[sizeof(textsegment.segname)-sizeof(uint64_t)]); //Modifying this will cause some apps to crash
    uint64_t* rd2 = (uint64_t*)&(firstsection.segname[sizeof(firstsection.segname)-sizeof(uint64_t)]);
    JBLogDebug("__TEXT: %llx,%llx, %016llX %016llX\n", textsegoffset, textsegment.fileoff, *rd, *rd2);

    CS_SuperBlob *superblob = macho_read_code_signature(macho);
    if (!superblob) {
        JBLogError("Error: failed to read code signature: %s\n", inputPath);
		fat_free(fat);
        return -1;
    }

    JBLogDebug("super blob: %x %x %d\n", superblob->magic, BIG_TO_HOST(superblob->length), BIG_TO_HOST(superblob->count));

    uint32_t superLength = BIG_TO_HOST(superblob->length);
	uint32_t blobCount = BIG_TO_HOST(superblob->count);
	if (superLength < sizeof(*superblob) || superLength > linkedit.datasize ||
		blobCount > (superLength - sizeof(*superblob)) / sizeof(CS_BlobIndex)) {
		free(superblob); fat_free(fat); return -1;
	}
	for (uint32_t i = 0; i < blobCount; i++) {
		uint32_t blobOffset = BIG_TO_HOST(superblob->index[i].offset);
		if (blobOffset > superLength || 8 > superLength - blobOffset) {
			free(superblob); fat_free(fat); return -1;
		}
		uint32_t blobLength;
		memcpy(&blobLength, (uint8_t *)superblob + blobOffset + 4, sizeof(blobLength));
		blobLength = BIG_TO_HOST(blobLength);
		if (blobLength < 8 || blobLength > superLength - blobOffset) {
			free(superblob); fat_free(fat); return -1;
		}
	}
    CS_DecodedSuperBlob *decodedSuperblob = csd_superblob_decode(superblob);
	if(!decodedSuperblob) {
		JBLogError("Error: failed to decode superblob: %s\n", inputPath);
		free(superblob);
		fat_free(fat);
		return -1;
	}

    int retval=-1;
	do
	{
		CS_DecodedBlob *bestCDBlob = csd_superblob_find_best_code_directory(decodedSuperblob);
		if(!bestCDBlob) {
			JBLogError("Error: failed to find best code directory: %s\n", inputPath);
			break;
		}

		if (isRemovableBundlePath(inputPath) && !hasTrollstoreLiteMarker(inputPath) && !hasJailFoolsMarker(inputPath)) break;
		CS_CodeDirectory directory;
		if (csd_blob_read(bestCDBlob, 0, sizeof(directory), &directory) != 0) break;
		CODE_DIRECTORY_APPLY_BYTE_ORDER(&directory, BIG_TO_HOST_APPLIER);
		if (directory.length < sizeof(directory) || directory.length > csd_blob_get_size(bestCDBlob) ||
			directory.hashOffset < sizeof(directory) || directory.hashOffset > directory.length ||
			directory.hashSize > directory.length - directory.hashOffset) break;

		uint32_t blobOffset = 0;
		for (uint32_t i = 0; i < blobCount; i++) {
			if (BIG_TO_HOST(superblob->index[i].type) == bestCDBlob->type) {
				blobOffset = BIG_TO_HOST(superblob->index[i].offset);
				break;
			}
		}
		if (!blobOffset || blobOffset > superLength || directory.length > superLength - blobOffset) break;
		uint64_t sliceOffset = macho->archDescriptor.offset;
		size_t fileSize = memory_stream_get_size(fat->stream);
		uint64_t signatureOffset = (uint64_t)linkedit.dataoff + blobOffset;
		if (sliceOffset > fileSize || signatureOffset > fileSize - sliceOffset ||
			directory.length > fileSize - sliceOffset - signatureOffset || firstsectoffset > fileSize - sliceOffset ||
			sizeof(firstsection) > fileSize - sliceOffset - firstsectoffset) break;

		struct section_64 originalSection = firstsection;
		*rd2 = jbinfo(jbrand);
		uint8_t pageHash[CC_SHA384_DIGEST_LENGTH] = {0};
		if (recdhash_prepare_page_hash(macho, &directory, firstsectoffset, &firstsection, pageHash) != 0) break;
		uint8_t *originalDirectory = malloc(directory.length);
		uint8_t *newDirectory = malloc(directory.length);
		if (!originalDirectory || !newDirectory) { free(originalDirectory); free(newDirectory); break; }
		uint64_t directoryOffset = sliceOffset + signatureOffset;
		uint64_t sectionOffset = sliceOffset + firstsectoffset;
		if (memory_stream_read(fat->stream, directoryOffset, directory.length, originalDirectory) != 0) {
			free(originalDirectory); free(newDirectory); break;
		}
		memcpy(newDirectory, originalDirectory, directory.length);
		memcpy(newDirectory + directory.hashOffset, pageHash, directory.hashSize);
		if (ksymbol(SPTMArgs) && csd_superblob_is_adhoc_signed(decodedSuperblob)) {
			char *teamId = csd_code_directory_copy_team_id(bestCDBlob, NULL);
			bool hasTeamId = teamId != NULL;
			free(teamId);
			uint32_t flags = HOST_TO_BIG(hasTeamId ? (directory.flags & ~CS_ADHOC) : (directory.flags | CS_ADHOC));
			memcpy(newDirectory + offsetof(CS_CodeDirectory, flags), &flags, sizeof(flags));
		}
		uint8_t newHash[CS_CDHASH_LEN];
		if (calc_cdhash(newDirectory, directory.length, directory.hashType, newHash) == 0) {
			bool changed = memcmp(&firstsection, &originalSection, sizeof(firstsection)) ||
				memcmp(newDirectory, originalDirectory, directory.length);
			retval = 0;
			if (changed) {
				// 最后写成功标记；即使上次只写了一半，也由上面的内容校验修复。
				if (memory_stream_write(fat->stream, directoryOffset, directory.length, newDirectory) != 0 ||
					memory_stream_write(fat->stream, sectionOffset, sizeof(firstsection), &firstsection) != 0) {
					int restoreDirectory = memory_stream_write(fat->stream, directoryOffset, directory.length, originalDirectory);
					int restoreSection = memory_stream_write(fat->stream, sectionOffset, sizeof(originalSection), &originalSection);
					if (restoreDirectory != 0 || restoreSection != 0) JBLogError("Failed to restore partial signature update: %s", inputPath);
					retval = -1;
				}
			}
			if (retval == 0 && cdhashOut) memcpy(cdhashOut, newHash, sizeof(newHash));
		}
		free(originalDirectory);
		free(newDirectory);
	} while(0);

	csd_superblob_free(decodedSuperblob);

	free(superblob);

	fat_free(fat); //will release MemoryStream and MachO(s)

	if (retval == 0) { // ios18.4+ dyld will check this (dyld patch enabled)
		struct timespec times[2] = { orig_st.st_atimespec, orig_st.st_mtimespec };
		utimensat(AT_FDCWD, inputPath, times, 0);
	}

	return retval;
}
