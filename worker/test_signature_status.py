#!/usr/bin/env python3
"""真实三态签名解析与 ChOma 回归，区分跳过和读取、解码、散列失败。"""

from pathlib import Path
import os
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
from test_spawn_persona_guard import ROOT, extract_function

PREFIX = r"""
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <choma/Fat.h>
#include <choma/MachO.h>
#include <choma/CodeDirectory.h>
#include <choma/CSBlob.h>
static int fault, reads, decodes, hashes, releases;
/* 默认使用实际命令枚举，只注入返回失败。 */
static int enumerate_probe(MachO *macho, void (^block)(struct load_command, uint64_t, void *, bool *)) {
    if (fault == 1) return -1;
    return macho_enumerate_load_commands(macho, block);
}
/* 读取故障不会变成没有签名；无故障时走真实切片范围检查。 */
static CS_SuperBlob *read_probe(MachO *macho) {
    reads++;
    if (fault == 2) { errno = EIO; return NULL; }
    return macho_read_code_signature(macho);
}
/* 解码失败作为独立故障，其他用例使用真实解码。 */
static CS_DecodedSuperBlob *decode_probe(CS_SuperBlob *blob) {
    decodes++;
    return fault == 3 ? NULL : csd_superblob_decode(blob);
}
/* 模拟散列错误，验证三态 helper 不将失败解释为跳过。 */
static int hash_probe(CS_DecodedSuperBlob *blob, void *out, int *type) {
    hashes++;
    return fault == 4 ? -1 : csd_superblob_calculate_best_cdhash(blob, out, type);
}
/* 记录解码对象的真实释放。 */
static void free_probe(CS_DecodedSuperBlob *blob) { releases++; csd_superblob_free(blob); }
#define macho_enumerate_load_commands enumerate_probe
#define macho_read_code_signature read_probe
#define csd_superblob_decode decode_probe
#define csd_superblob_calculate_best_cdhash hash_probe
#define csd_superblob_free free_probe
"""

CASES = r"""
#undef macho_enumerate_load_commands
#undef macho_read_code_signature
#undef csd_superblob_decode
#undef csd_superblob_calculate_best_cdhash
#undef csd_superblob_free
enum { SIGNATURE_OFFSET = 64 };
/* 构造实际可解析的无签名、adhoc 和带 CMS wrapper 的 Mach-O。 */
static size_t fixture(uint8_t bytes[1024], int kind) {
    memset(bytes, 0, 1024);
    struct mach_header_64 *header = (void *)bytes;
    *header = (struct mach_header_64){.magic=MH_MAGIC_64, .cputype=CPU_TYPE_ARM64,
        .cpusubtype=CPU_SUBTYPE_ARM64_ALL, .filetype=MH_EXECUTE,
        .ncmds=kind ? 1 : 0, .sizeofcmds=kind ? sizeof(struct linkedit_data_command) : 0};
    if (!kind) return SIGNATURE_OFFSET;
    uint32_t count = kind == 2 ? 2 : 1;
    uint32_t directoryOffset = sizeof(CS_SuperBlob) + count * sizeof(CS_BlobIndex);
    uint32_t directorySize = sizeof(CS_CodeDirectory) + CC_SHA256_DIGEST_LENGTH;
    uint32_t signatureSize = directoryOffset + directorySize + (kind == 2 ? 9 : 0);
    struct linkedit_data_command *command = (void *)(bytes + sizeof(*header));
    *command = (struct linkedit_data_command){.cmd=LC_CODE_SIGNATURE, .cmdsize=sizeof(*command),
        .dataoff=SIGNATURE_OFFSET, .datasize=signatureSize};
    CS_SuperBlob *blob = (void *)(bytes + SIGNATURE_OFFSET);
    blob->magic = HOST_TO_BIG(CSMAGIC_EMBEDDED_SIGNATURE);
    blob->length = HOST_TO_BIG(signatureSize);
    blob->count = HOST_TO_BIG(count);
    blob->index[0] = (CS_BlobIndex){.type=HOST_TO_BIG(CSSLOT_CODEDIRECTORY), .offset=HOST_TO_BIG(directoryOffset)};
    CS_CodeDirectory directory = {.magic=CSMAGIC_CODEDIRECTORY, .length=directorySize,
        .version=0x20200, .flags=kind == 2 ? 0 : 2, .hashOffset=sizeof(CS_CodeDirectory),
        .nCodeSlots=1, .codeLimit=SIGNATURE_OFFSET, .hashSize=CC_SHA256_DIGEST_LENGTH,
        .hashType=CS_HASHTYPE_SHA256_256, .pageSize=6};
    CODE_DIRECTORY_APPLY_BYTE_ORDER(&directory, HOST_TO_BIG_APPLIER);
    memcpy((uint8_t *)blob + directoryOffset, &directory, sizeof(directory));
    CC_SHA256(bytes, SIGNATURE_OFFSET, (uint8_t *)blob + directoryOffset + sizeof(directory));
    if (kind == 2) {
        uint32_t wrapperOffset = directoryOffset + directorySize;
        blob->index[1] = (CS_BlobIndex){.type=HOST_TO_BIG(CSSLOT_SIGNATURESLOT), .offset=HOST_TO_BIG(wrapperOffset)};
        CS_GenericBlob wrapper = {.magic=HOST_TO_BIG(CSMAGIC_BLOBWRAPPER), .length=HOST_TO_BIG(9)};
        memcpy((uint8_t *)blob + wrapperOffset, &wrapper, sizeof(wrapper));
        *((uint8_t *)blob + wrapperOffset + 8) = 1;
    }
    return SIGNATURE_OFFSET + signatureSize;
}
/* 通过真实文件和 Fat 初始化进入待测 helper，并核对输出及资源释放。 */
static void run(const char *path, uint8_t *bytes, size_t size, int failure, int expected, int expectedReleases) {
    FILE *file = fopen(path, "wb");
    assert(file && fwrite(bytes, 1, size, file) == size && fclose(file) == 0);
    Fat *fat = fat_init_from_path(path);
    assert(fat && fat->slicesCount == 1);
    fault=failure; reads=decodes=hashes=releases=0;
    cdhash_t hash;
    memset(hash, 0xA5, sizeof(hash));
    int result = macho_collect_adhoc_cdhash(fat->slices[0], hash);
    assert(result == expected && releases == expectedReleases);
    if (expected <= 0) {
        for (size_t i=0; i<sizeof(hash); i++) assert(hash[i] == 0xA5);
    } else {
        uint8_t expectedHash[CC_SHA256_DIGEST_LENGTH];
        CS_SuperBlob *blob=(void *)(bytes + SIGNATURE_OFFSET);
        CS_CodeDirectory *directory=(void *)((uint8_t *)blob + BIG_TO_HOST(blob->index[0].offset));
        CC_SHA256(directory, BIG_TO_HOST(directory->length), expectedHash);
        assert(!memcmp(hash, expectedHash, sizeof(hash)));
    }
    if (failure == 1) assert(reads == 0);
    fat_free(fat);
}
/* 不能把未签名/CMS、损坏签名和 I/O 故障合并成同一个状态。 */
int main(int argc, char **argv) {
    uint8_t bytes[1024];
    size_t size = fixture(bytes, 0);
    run(argv[1], bytes, size, 0, 0, 0);
    assert(reads == 0 && decodes == 0 && hashes == 0);
    size = fixture(bytes, 2);
    run(argv[1], bytes, size, 0, 0, 1);
    assert(hashes == 0);
    size = fixture(bytes, 1);
    run(argv[1], bytes, size, 0, 1, 1);
    for (int failure = 1; failure <= 4; failure++)
        run(argv[1], bytes, size, failure, -1, failure == 4 ? 1 : 0);
    struct linkedit_data_command *command = (void *)(bytes + sizeof(struct mach_header_64));
    command->datasize = 8;
    run(argv[1], bytes, size, 0, -1, 0);
    size = fixture(bytes, 1); command->dataoff = (uint32_t)size - 4;
    run(argv[1], bytes, size, 0, -1, 0);
    size = fixture(bytes, 1);
    CS_SuperBlob *blob = (void *)(bytes + SIGNATURE_OFFSET);
    blob->index[0].offset = HOST_TO_BIG((uint32_t)size);
    run(argv[1], bytes, size, 0, -1, 0);
    size = fixture(bytes, 1); blob->magic = 0;
    run(argv[1], bytes, size, 0, -1, 0);
    size = fixture(bytes, 1);
    CS_CodeDirectory *directory = (void *)((uint8_t *)blob + BIG_TO_HOST(blob->index[0].offset));
    directory->hashType = 99;
    run(argv[1], bytes, size, 0, -1, 1);
    puts("PASS signature status: unsigned/CMS skip, adhoc hash, enumerate/read/decode/hash errors, short/out-of-slice/malformed blobs");
    return 0;
}
"""


def main():
    """抽取实际三态 helper，链接真实 ChOma，并用故障变体验证断言。"""
    source = (ROOT / "BaseBin/libjailbreak/src/signatures.c").read_text()
    adhoc = extract_function(source, "bool csd_superblob_is_adhoc_signed(")
    actual = extract_function(source, "static int macho_collect_adhoc_cdhash(")
    with tempfile.TemporaryDirectory(prefix="signature-status-", dir=ROOT / "worker") as temporary:
        directory = Path(temporary)
        (directory / "choma").symlink_to(ROOT / "BaseBin/ChOma/src", target_is_directory=True)
        for name, implementation in (
            ("current", actual),
            ("skip-read-error", actual.replace("if (!blob) return -1;", "if (!blob) return 0;")),
            ("skip-decode-error", actual.replace("if (!decoded) return -1;", "if (!decoded) return 0;")),
            ("skip-hash-error", actual.replace("== 0 ? 1 : -1;", "== 0 ? 1 : 0;")),
        ):
            harness = directory / (name + ".c")
            binary = directory / name
            harness.write_text(PREFIX + adhoc + implementation + CASES)
            command = [os.environ.get("CC", "clang"), "-fblocks", "-fsanitize=address,undefined",
                       "-O1", "-g", "-Wno-deprecated-declarations", "-I", str(directory),
                       str(harness), *map(str, (ROOT / "BaseBin/ChOma/src").glob("*.c")),
                       "-framework", "CoreFoundation", "-o", str(binary)]
            subprocess.run(command, check=True)
            result = subprocess.run([str(binary), str(directory / "fixture")], capture_output=True,
                                    text=True, timeout=20, env={**os.environ, "ASAN_OPTIONS": "detect_leaks=0"})
            if name == "current":
                if result.returncode:
                    raise SystemExit(result.stderr or f"Current source failed: {result.returncode}")
                print(result.stdout.strip())
            elif result.returncode == 0:
                raise SystemExit("Mutation unexpectedly accepted: " + name)
            else:
                print("PASS regression mutation rejected: " + name)


if __name__ == "__main__":
    main()
