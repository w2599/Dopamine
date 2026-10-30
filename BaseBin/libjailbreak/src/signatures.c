#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <choma/MachO.h>
#include <choma/Fat.h>
#include <choma/MemoryStream.h>
#include <choma/FileStream.h>
#include <choma/CSBlob.h>
#include <choma/CodeDirectory.h>
#include <choma/Util.h>
#include <choma/Host.h>
#include <mach-o/dyld.h>
#include <libkern/OSByteOrder.h>
#include "trustcache.h"
#include "util.h"
#include "kernel.h"
#include "primitives.h"
#include "codesign.h"

#include <libroothider/libroothider.h>

// 判断宿主是否可能映射该架构，旧 arm64e ABI 仅允许非主程序。
bool macho_is_mappable(MachO *macho)
{
	// Determine if there is any case in which the macho could be mapped

	static cpu_type_t hostCpuType;
	static cpu_subtype_t hostCpuSubtype;
	static dispatch_once_t onceToken = 0;
	dispatch_once(&onceToken, ^{
		host_get_cpu_information(&hostCpuType, &hostCpuSubtype);
	});

	bool hostIsArm64e = (hostCpuType == CPU_TYPE_ARM64) && ((hostCpuSubtype & ~0xff000000) == CPU_SUBTYPE_ARM64E);

	struct mach_header *header = macho_get_mach_header(macho);

	cpu_type_t cputype = header->cputype;
	cpu_subtype_t cpusubtype = header->cpusubtype;
	bool isLibrary = (header->filetype != MH_EXECUTE);

	if (cputype != CPU_TYPE_ARM64) return false;

	if (hostIsArm64e) {
		if (cpusubtype == (CPU_SUBTYPE_ARM64E | CPU_SUBTYPE_ARM64E_ABI_V2)) {
			// New arm64e ABI always mappable on arm64e
			return true;
		}
		else if (cpusubtype == CPU_SUBTYPE_ARM64E && isLibrary) {
			// Old arm64e ABI only mappable for libraries on arm64e iOS 14.6+
			return true;
		}
	}

	// Anything arm64 is always mappable on all dvices
	if ((cpusubtype == CPU_SUBTYPE_ARM64_V8) || (cpusubtype == CPU_SUBTYPE_ARM64_ALL)) return true;

	return false;
}

bool csd_superblob_is_adhoc_signed(CS_DecodedSuperBlob *superblob)
{
	CS_DecodedBlob *wrapperBlob = csd_superblob_find_blob(superblob, CSSLOT_SIGNATURESLOT, NULL);
	if (wrapperBlob) {
		if (csd_blob_get_size(wrapperBlob) > 8) {
			return false;
		}
	}
	return true;
}

bool code_signature_calculate_adhoc_cdhash(CS_SuperBlob *superblob, cdhash_t cdhashOut)
{
	bool isAdhocSigned = false;

	CS_DecodedSuperBlob *decodedSuperblob = csd_superblob_decode(superblob);
	if (decodedSuperblob) {
		if (csd_superblob_is_adhoc_signed(decodedSuperblob)) {
			if (csd_superblob_calculate_best_cdhash(decodedSuperblob, cdhashOut, NULL) == 0) {
				isAdhocSigned = true;
			}
		}
		csd_superblob_free(decodedSuperblob);
	}

	return isAdhocSigned;
}

// 返回 1 表示需信任的 adhoc 签名，0 表示无需处理，-1 表示读取或解析失败。
static int macho_collect_adhoc_cdhash(MachO *macho, cdhash_t hash)
{
	__block bool hasSignature = false;
	int r = macho_enumerate_load_commands(macho, ^(struct load_command command, uint64_t offset, void *data, bool *stop) {
		if (command.cmd == LC_CODE_SIGNATURE) { hasSignature = true; *stop = true; }
	});
	if (r != 0) return -1;
	if (!hasSignature) return 0;
	CS_SuperBlob *blob = macho_read_code_signature(macho);
	if (!blob) return -1;
	CS_DecodedSuperBlob *decoded = csd_superblob_decode(blob);
	free(blob);
	if (!decoded) return -1;
	int result = 0;
	if (csd_superblob_is_adhoc_signed(decoded)) {
		result = csd_superblob_calculate_best_cdhash(decoded, hash, NULL) == 0 ? 1 : -1;
	}
	csd_superblob_free(decoded);
	return result;
}

// 保留已有布尔接口，收集流程使用上面的三态接口传播错误。
bool macho_parse_code_signature(MachO *macho, cdhash_t hash)
{
	return macho_collect_adhoc_cdhash(macho, hash) == 1;
}

// 收集全部可映射切片；任一修改失败都丢弃部分结果并返回错误。
int fat_collect_untrusted_cdhashes(Fat *fat, cdhash_t **cdhashesOut, uint32_t *cdhashCountOut)
{
	if (!cdhashesOut || !cdhashCountOut) return -1;
	*cdhashesOut = NULL;
	*cdhashCountOut = 0;
	if (!fat || !fat->stream || !fat->stream->context) return -1;
	FileStreamContext *context = (FileStreamContext *)fat->stream->context;
	char filepath[PATH_MAX] = {0};
	if (fcntl(context->fd, F_GETPATH, filepath) != 0) return -1;
	if (string_has_prefix(filepath, "/private/preboot/Cryptexes/") ||
		(isRemovableBundlePath(filepath) && !hasTrollstoreLiteMarker(filepath) && !hasJailFoolsMarker(filepath))) return 0;

	const char *filePath = filepath;
	__block cdhash_t *cdhashes = NULL;
	__block uint32_t count = 0;
	__block int result = 0;
	fat_enumerate_slices(fat, ^(MachO *macho, bool *stop) {
		cdhash_t hash;
		if (!macho_is_mappable(macho)) return;
		int signatureResult = macho_collect_adhoc_cdhash(macho, hash);
		if (signatureResult < 0) { result = -1; *stop = true; return; }
		if (signatureResult == 0 || is_cdhash_trustcached(hash)) return;
		if (ensure_randomized_cdhash_for_slice(filePath, macho->archDescriptor.offset, hash) != 0 || count == UINT32_MAX) {
			result = -1;
			*stop = true;
			return;
		}
		cdhash_t *expanded = realloc(cdhashes, ((size_t)count + 1) * sizeof(cdhash_t));
		if (!expanded) { result = -1; *stop = true; return; }
		cdhashes = expanded;
		memcpy(cdhashes[count++], hash, sizeof(hash));
	});
	if (result != 0) { free(cdhashes); return result; }
	*cdhashesOut = cdhashes;
	*cdhashCountOut = count;
	return 0;
}

// 借用文件描述符解析并传递收集错误。
int file_collect_untrusted_cdhashes(int fd, cdhash_t **cdhashesOut, uint32_t *cdhashCountOut)
{
	if (!cdhashesOut || !cdhashCountOut) return -1;
	*cdhashesOut = NULL;
	*cdhashCountOut = 0;
	MemoryStream *stream = file_stream_init_from_file_descriptor(fd, 0, FILE_STREAM_SIZE_AUTO, 0);
	if (!stream) return -1;
	Fat *fat = fat_init_from_memory_stream(stream);
	if (!fat) { memory_stream_free(stream); return -1; }
	int result = fat_collect_untrusted_cdhashes(fat, cdhashesOut, cdhashCountOut);
	fat_free(fat);
	return result;
}

// 打开路径并在所有返回路径关闭描述符。
int file_collect_untrusted_cdhashes_by_path(const char *path, cdhash_t **cdhashesOut, uint32_t *cdhashCountOut)
{
	if (!cdhashesOut || !cdhashCountOut) return -1;
	*cdhashesOut = NULL;
	*cdhashCountOut = 0;
	int fd = open(path, O_RDONLY);
	if (fd < 0) return -1;
	int result = file_collect_untrusted_cdhashes(fd, cdhashesOut, cdhashCountOut);
	close(fd);
	return result;
}

void fat_collect_signatures(Fat *fat, struct siginfo **sigInfosOut, uint32_t *sigInfoCountOut)
{
	__block struct siginfo *sigInfos = NULL;
	__block uint32_t sigInfoCount = 0;
	fat_enumerate_slices(fat, ^(MachO *macho, bool *stop) {
		if (macho_is_mappable(macho)) {
			CS_SuperBlob *superblob = macho_read_code_signature(macho);
			if (superblob) {
				sigInfoCount++;
				sigInfos = realloc(sigInfos, sigInfoCount * sizeof(struct siginfo));
				struct siginfo *curSigInfo = &sigInfos[sigInfoCount-1];

				curSigInfo->source = SIGNATURE_SOURCE_ALLOCATION;
				curSigInfo->signature.fs_file_start = macho->archDescriptor.offset;
				curSigInfo->signature.fs_blob_start = superblob;
				curSigInfo->signature.fs_blob_size = OSSwapBigToHostInt32(superblob->length);
			}
		}
	});

	if (sigInfosOut) *sigInfosOut = sigInfos;
	if (sigInfoCountOut) *sigInfoCountOut = sigInfoCount;
}

void file_collect_signatures(int fd, struct siginfo **sigInfosOut, uint32_t *sigInfoCountOut)
{
	MemoryStream *s = file_stream_init_from_file_descriptor(fd, 0, FILE_STREAM_SIZE_AUTO, 0);
	if (!s) return;

	Fat *fat = fat_init_from_memory_stream(s);
	if (!fat) {
		memory_stream_free(s);
		return;
	}

	fat_collect_signatures(fat, sigInfosOut, sigInfoCountOut);

	fat_free(fat);
}


CS_SuperBlob *siginfo_resolve_superblob(struct siginfo *siginfo, int pid, int fd)
{
	if (!siginfo) return NULL;
	if (siginfo->signature.fs_blob_size == 0) return NULL;

	size_t superblobSize = siginfo->signature.fs_blob_size;
	CS_SuperBlob *superblob = malloc(superblobSize);
	if (!superblob) return NULL;

	bool success = false;

	switch (siginfo->source) {
		case SIGNATURE_SOURCE_ALLOCATION: {
			memcpy(superblob, siginfo->signature.fs_blob_start, superblobSize);
			success = true;
			break;
		}
		case SIGNATURE_SOURCE_FILE: {
			uintptr_t superblobStart = siginfo->signature.fs_file_start + (uintptr_t)siginfo->signature.fs_blob_start;
			uintptr_t superblobEnd   = superblobStart + superblobSize;
			struct stat st = {};

        	if (fstat(fd, &st) != 0) break;
			if (superblobEnd > st.st_size) break;
			if (lseek(fd, superblobStart, SEEK_SET) != superblobStart) break;
			if (read(fd, superblob, superblobSize) != superblobSize) break;

			success = true;
			break;
		}
		case SIGNATURE_SOURCE_PROC: {
			uint64_t proc = proc_find(pid);

			if (!proc) break;
			if (proc_vreadbuf(proc, siginfo->signature.fs_blob_start, superblob, superblobSize) != 0) break;

			success = true;
			break;
		}
	}

	if (!success) {
		free(superblob);
		superblob = NULL;
	}

	return superblob;
}

// 信任签名并按需附加，缓存追加失败时立即返回错误。
int trust_signatures(int pid, int fd, struct siginfo *sigInfos, uint32_t sigInfoCount)
{
	if (sigInfoCount == 0) return 0;

    cdhash_t *cdhashes = malloc(sizeof(cdhash_t) * sigInfoCount);
	if (!cdhashes) return -2;
    uint32_t cdhashesCount = 0;

	struct siginfo **sigInfosToAttach = malloc(sizeof(struct siginfo *) * sigInfoCount);
	if (!sigInfosToAttach) return -2;
	uint32_t sigInfosToAttachCount = 0;

	for (uint32_t i = 0; i < sigInfoCount; i++) {
		struct siginfo *curSigInfo = &sigInfos[i];
		CS_SuperBlob *superblob = siginfo_resolve_superblob(curSigInfo, pid, fd);
		if (superblob) {
			CS_DecodedSuperBlob *decodedSuperblob = csd_superblob_decode(superblob);
			free(superblob);

			if (decodedSuperblob) {
				if (csd_superblob_is_adhoc_signed(decodedSuperblob)) {
					CS_DecodedBlob *bestCDBlob = csd_superblob_find_best_code_directory(decodedSuperblob);
					if (bestCDBlob) {
						if (ksymbol(SPTMArgs)) {
							uint32_t flags = csd_code_directory_get_flags(bestCDBlob);
							bool hasTeamId = false;
							char *teamId = csd_code_directory_copy_team_id(bestCDBlob, NULL);
							if (teamId) {
								free(teamId);
								hasTeamId = true;
							}

							if (!!(flags & CS_ADHOC) == hasTeamId) {
								// According to TXM, either CS_ADHOC or TeamID is fine
								// Both or neither are not
								// Neither: We give it CS_ADHOC
								// Both: We strip CS_ADHOC

								if (curSigInfo->source == SIGNATURE_SOURCE_ALLOCATION) {
									if (hasTeamId) {
										// Has both TeamID and CS_ADHOC, strip CS_ADHOC
										csd_code_directory_set_flags(bestCDBlob, flags & ~CS_ADHOC);
									}
									else {
										// Has neither TeamID or CS_ADHOC, add CS_ADHOC
										csd_code_directory_set_flags(bestCDBlob, flags | CS_ADHOC);
									}

									free(curSigInfo->signature.fs_blob_start);
									superblob = csd_superblob_encode(decodedSuperblob);
									curSigInfo->signature.fs_blob_start = superblob;
									curSigInfo->signature.fs_blob_size = OSSwapBigToHostInt32(superblob->length);

									sigInfosToAttach[sigInfosToAttachCount++] = curSigInfo;
								}
								else {
									// If the signature does not reside inside our own address space, there is nothing we can do
									// Such a signature should have been caught by dyldhook so in reality this code path will probably never fire
									csd_superblob_free(decodedSuperblob);
									free(cdhashes);
									free(sigInfosToAttach);
									return -1;
								}
							}
						}

						cdhash_t cdhash;
						csd_code_directory_calculate_hash(bestCDBlob, &cdhash);
						if (!is_cdhash_trustcached(cdhash)) {
							memcpy(&cdhashes[cdhashesCount++], &cdhash, sizeof(cdhash_t));
						}
					}
				}
				csd_superblob_free(decodedSuperblob);
			}
		}
	}

	int r = 0;
	if (cdhashesCount > 0) {
		r = jb_trustcache_add_cdhashes(cdhashes, cdhashesCount);
		if (r != 0) {
			free(sigInfosToAttach);
			free(cdhashes);
			return r;
		}
	}

	if (sigInfosToAttachCount > 0) {
		// For every signature we have modified, we need to attach them to fd now
		for (uint32_t i = 0; i < sigInfosToAttachCount; i++) {
			struct siginfo *curSigInfo = sigInfosToAttach[i];
			int fd_r = fd_attach_signature(fd, &curSigInfo->signature);
			if (fd_r != 0) r = fd_r;
		}
	}
	
	free(sigInfosToAttach);
	free(cdhashes);
	return r;
}
