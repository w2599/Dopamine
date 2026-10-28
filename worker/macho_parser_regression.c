#include "BufferedStream.h"
#include "CSBlob.h"
#include "Fat.h"
#include "FileStream.h"
#include "MachO.h"
#include "MachOByteOrder.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>

static int (*original_read)(MemoryStream *, uint64_t, size_t, void *);
static unsigned read_count;
static unsigned fail_read;

// 在真实流的指定读取点注入失败，保留其余读取行为。
static int failing_read(MemoryStream *stream, uint64_t offset, size_t size, void *out)
{
    if (++read_count == fail_read) return -1;
    return original_read(stream, offset, size, out);
}

// 同时检查文件流、缓冲流和可写初始化的解析结果。
static void check_file(const char *path, bool expected, bool writable)
{
    MemoryStream *file = file_stream_init_from_path(path, 0, FILE_STREAM_SIZE_AUTO, 0);
    assert(file);
    size_t size = memory_stream_get_size(file);
    void *bytes = malloc(size ?: 1);
    assert(bytes);
    if (size) assert(memory_stream_read(file, 0, size, bytes) == 0);
    MemoryStream *buffer = buffered_stream_init_from_buffer(bytes, size, 0);
    assert(buffer);
    free(bytes);
    struct fat_arch_64 arch = {.size = size};
    MachO *macho = macho_init(file, arch);
    if ((macho != NULL) != expected) {
        fprintf(stderr, "file parse mismatch: %s (expected %d)\n", path, expected);
        abort();
    }
    if (macho) macho_free(macho);
    macho = macho_init(buffer, arch);
    if ((macho != NULL) != expected) {
        fprintf(stderr, "buffer parse mismatch: %s (expected %d)\n", path, expected);
        abort();
    }
    if (macho) macho_free(macho);
    if (writable) {
        macho = macho_init_for_writing(path);
        if ((macho != NULL) != expected) {
            fprintf(stderr, "writable parse mismatch: %s (expected %d)\n", path, expected);
            abort();
        }
        if (macho) macho_free(macho);
    }
}

// 验证命令读取失败不会被枚举或初始化当作成功。
static void check_read_errors(const char *path)
{
    for (unsigned failure = 1; failure <= 2; failure++) {
        MemoryStream *stream = file_stream_init_from_path(path, 0, FILE_STREAM_SIZE_AUTO, 0);
        MachO *macho = macho_init(stream, (struct fat_arch_64){0});
        assert(macho);
        original_read = stream->read;
        read_count = 0;
        fail_read = failure;
        stream->read = failing_read;
        __block unsigned callbacks = 0;
        assert(macho_enumerate_load_commands(macho, ^(struct load_command command, uint64_t offset, void *bytes, bool *stop) {
            callbacks++;
        }) != 0);
        assert(callbacks == 0);
        macho_free(macho);
    }
    for (unsigned failure = 1; failure <= 3; failure++) {
        MemoryStream *stream = file_stream_init_from_path(path, 0, FILE_STREAM_SIZE_AUTO, 0);
        original_read = stream->read;
        read_count = 0;
        fail_read = failure;
        stream->read = failing_read;
        assert(macho_init(stream, (struct fat_arch_64){0}) == NULL);
    }
}

// 真实文件流即使后面仍有数据，也不能读取声明切片范围外的命令。
static void check_trimmed_stream(const char *path)
{
    MemoryStream *stream = file_stream_init_from_path(path, 0, FILE_STREAM_SIZE_AUTO, 0);
    size_t size = memory_stream_get_size(stream);
    assert(size > sizeof(struct mach_header_64));
    assert(memory_stream_trim(stream, 0, size - sizeof(struct mach_header_64)) == 0);
    assert(macho_init(stream, (struct fat_arch_64){0}) == NULL);
}

// 对真实文件流和缓冲流检查签名边界，并解码合法的子 blob。
static void check_signature_file(const char *path, char mode)
{
    MemoryStream *streams[2];
    streams[0] = file_stream_init_from_path(path, 0, FILE_STREAM_SIZE_AUTO, 0);
    assert(streams[0]);
    size_t size = memory_stream_get_size(streams[0]);
    void *bytes = malloc(size);
    assert(bytes && memory_stream_read(streams[0], 0, size, bytes) == 0);
    streams[1] = buffered_stream_init_from_buffer(bytes, size, 0);
    assert(streams[1]);
    free(bytes);
    for (unsigned i = 0; i < 2; i++) {
        if (mode == 't') assert(memory_stream_trim(streams[i], 0, 1) == 0);
        MachO *macho = macho_init(streams[i], (struct fat_arch_64){0});
        assert(macho);
        if (mode == 'f') {
            original_read = streams[i]->read;
            read_count = 0;
            fail_read = 3;
            streams[i]->read = failing_read;
        }
        CS_SuperBlob *signature = macho_read_code_signature(macho);
        if ((signature != NULL) != (mode == '1')) {
            fprintf(stderr, "signature parse mismatch: %s (mode %c)\n", path, mode);
            abort();
        }
        if (signature) {
            CS_DecodedSuperBlob *decoded = csd_superblob_decode(signature);
            assert(decoded);
            uint32_t count = 0;
            for (CS_DecodedBlob *blob = decoded->firstBlob; blob; blob = blob->next) {
                assert(csd_blob_get_size(blob) >= sizeof(CS_GenericBlob));
                count++;
            }
            assert(count == BIG_TO_HOST(signature->count));
            csd_superblob_free(decoded);
            free(signature);
        }
        macho_free(macho);
    }
}

// fd 0 与其他描述符遵循同样的所有权：借用不关闭，自有在正常释放时关闭。
static void check_fd_zero_ownership(const char *path)
{
    int savedInput = dup(STDIN_FILENO);
    close(STDIN_FILENO);
    assert(open(path, O_RDONLY) == STDIN_FILENO);
    MemoryStream *borrowed = file_stream_init_from_file_descriptor_nodup(STDIN_FILENO, 0, FILE_STREAM_SIZE_AUTO, 0);
    assert(borrowed);
    memory_stream_free(borrowed);
    assert(fcntl(STDIN_FILENO, F_GETFD) >= 0);
    close(STDIN_FILENO);
    MemoryStream *owned = file_stream_init_from_path(path, 0, FILE_STREAM_SIZE_AUTO, 0);
    assert(owned && ((FileStreamContext *)owned->context)->fd == STDIN_FILENO);
    MachO *macho = macho_init(owned, (struct fat_arch_64){0});
    assert(macho);
    macho_free(macho);
    assert(fcntl(STDIN_FILENO, F_GETFD) == -1 && errno == EBADF);
    if (savedInput >= 0) {
        assert(dup2(savedInput, STDIN_FILENO) == STDIN_FILENO);
        close(savedInput);
    }
}

// 运行持久化回归入口，s 前缀选择签名检查，其余参数选择 Mach-O 初始化。
int main(int argc, char **argv)
{
    assert(argc > 3 && (argc - 2) % 2 == 0);
    check_read_errors(argv[1]);
    check_trimmed_stream(argv[1]);
    check_fd_zero_ownership(argv[1]);
    unsigned parserCases = 0, signatureCases = 0;
    for (int i = 2; i < argc; i += 2) {
        if (argv[i][0] == 's') {
            check_signature_file(argv[i + 1], argv[i][1]);
            signatureCases++;
        }
        else {
            check_file(argv[i + 1], argv[i][0] == '1', argv[i][1] != 'r');
            parserCases++;
        }
    }
    printf("MachO parser: %u file cases, %u signature cases, read/trim failures and fd 0 ownership passed\n", parserCases, signatureCases);
    return 0;
}
