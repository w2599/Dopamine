#!/usr/bin/env python3
"""Compile the real ChOma sources with ASan/UBSan and test bounded local fixtures.

Run from any directory: python3 worker/macho_parser_regression.py
Only temporary files under worker/ are created; no device or build outputs are used.
"""

import os
from pathlib import Path
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "BaseBin/ChOma/src"


def header(commands, *, count=None, bits=64, filetype=1, flags=0):
    """创建命令数量和位宽明确的测试文件头。"""
    fields = [0xFEEDFACF if bits == 64 else 0xFEEDFACE,
              0x0100000C if bits == 64 else 7, 0, filetype,
              len(commands) if count is None else count,
              sum(map(len, commands)), flags]
    if bits == 64:
        fields.append(0)
    return struct.pack("<" + "I" * len(fields), *fields) + b"".join(commands)


def segment64(*, nsects=1, vmaddr=0x1000, vmsize=16, fileoff=184,
              filesize=16, addr=0x1000, size=16, offset=184, flags=0,
              reloff=0, nreloc=0, include_section=True):
    """创建带单节的 64 位段，字段可单独改变以覆盖边界。"""
    command_size = 72 + (80 if include_section else 0)
    segment = struct.pack("<II16sQQQQiiII", 0x19, command_size, b"__DATA",
                          vmaddr, vmsize, fileoff, filesize, 3, 3, nsects, 0)
    if include_section:
        segment += struct.pack("<16s16sQQIIIIIIII", b"__data", b"__DATA",
                               addr, size, offset, 0, reloff, nreloc, flags, 0, 0, 0)
    return segment


def segment32(*, nsects=1, include_section=True):
    """创建 x86 32 位段，验证位宽取自魔数而不是 ARM 子类型。"""
    segment = struct.pack("<II16sIIIIiiII", 1, 124 if include_section else 56,
                          b"__DATA", 0x1000, 16, 152, 16, 3, 3, nsects, 0)
    if include_section:
        segment += struct.pack("<16s16sIIIIIIIII", b"__data", b"__DATA",
                               0x1000, 16, 152, 0, 0, 0, 0, 0, 0)
    return segment


def replace_u32(data, offset, value):
    """修改独立字段，保留其余合法文件结构。"""
    result = bytearray(data)
    struct.pack_into("<I", result, offset, value)
    return bytes(result)


def signature(children):
    """创建带索引和不等长子 blob 的大端签名容器。"""
    offset = 12 + 8 * len(children)
    indices = []
    for slot, child in enumerate(children):
        indices.append(struct.pack(">II", 0x10000 + slot, offset))
        offset += len(child)
    return struct.pack(">III", 0xFADE0CC0, offset, len(children)) + b"".join(indices) + b"".join(children)


def replace_be32(data, offset, value):
    """独立改动大端签名长度、计数或索引字段。"""
    result = bytearray(data)
    struct.pack_into(">I", result, offset, value)
    return bytes(result)


def run():
    """构建真实解析器并执行正常、截断与读取失败用例。"""
    with tempfile.TemporaryDirectory(prefix="macho-parser-", dir=ROOT / "worker") as temporary:
        work = Path(temporary)
        binary = work / "macho_parser_regression"
        subprocess.run(["clang", "-fblocks", "-fsanitize=address,undefined",
                        "-fno-sanitize-recover=all", "-g", "-O1",
                        "-Wno-deprecated-declarations", f"-I{SOURCE}",
                        str(ROOT / "worker/macho_parser_regression.c"),
                        *map(str, sorted(SOURCE.glob("*.c"))),
                        "-framework", "CoreFoundation", "-o", str(binary)], check=True)
        arguments = []

        def case(name, data, expected=False, writable=True):
            """将固定大小测试数据写入独立临时文件。"""
            path = work / name
            path.write_bytes(data)
            arguments.extend([("1" if expected else "0") + ("" if writable else "r"), str(path)])
            return path

        valid = header([segment64()]) + bytes(16)
        valid_path = case("valid-64", valid, True)
        case("valid-32-x86", header([segment32()], bits=32) + bytes(16), True, False)
        case("valid-empty-64", header([]), True)
        case("valid-unknown", header([struct.pack("<II", 0x70000000, 8)]), True)
        case("valid-many-commands", header([struct.pack("<II", 0x70000000, 8)] * 1001), True)
        case("valid-large-command", header([struct.pack("<II", 8, 512 * 1024) + bytes(512 * 1024 - 8)]), True)
        case("valid-zero-fill", header([segment64(fileoff=0, filesize=0, offset=0xFFFFFFFF, flags=1)]), True)
        case("valid-gb-zero-fill", header([segment64(fileoff=0, filesize=0, offset=0xFFFFFFFF, flags=0xC)]), True)
        case("valid-thread-zero-fill", header([segment64(fileoff=0, filesize=0, offset=0xFFFFFFFF, flags=0x12)]), True)
        case("valid-cache-layout", header([segment64(fileoff=0x10000, offset=0x10000)], flags=0x80000000), True)
        for size in (0, 4, 27, 28, 31, 32, 39, 40, 103, 183, 184, 199):
            case(f"truncated-{size}", valid[:size])
        case("zero-command-size", replace_u32(valid, 36, 0))
        case("short-command-header", replace_u32(valid, 36, 4))
        case("short-segment-header", header([struct.pack("<II", 0x19, 8)]))
        case("short-symtab-header", header([struct.pack("<II", 2, 8)]))
        case("short-linkedit-header", header([struct.pack("<II", 0x1D, 8)]))
        case("command-past-region", replace_u32(valid, 36, 160))
        case("command-not-aligned", replace_u32(valid, 36, 151))
        case("commands-not-aligned", replace_u32(valid, 20, 151))
        case("too-many-commands", replace_u32(valid, 16, 30))
        case("missing-command", replace_u32(valid, 16, 2))
        case("unconsumed-command", replace_u32(valid, 16, 0))
        case("huge-command-size", replace_u32(valid, 36, 0xFFFFFFF8))
        case("huge-command-region", replace_u32(valid, 20, 0xFFFFFFF8))
        case("missing-section-64", header([segment64(include_section=False)]))
        case("extra-section-64", header([segment64(nsects=2)]) + bytes(16))
        case("huge-section-count-64", header([segment64(nsects=0xFFFFFFFF)]) + bytes(16))
        case("missing-section-32", header([segment32(include_section=False)], bits=32), writable=False)
        case("extra-section-32", header([segment32(nsects=2)], bits=32) + bytes(16), writable=False)
        case("huge-section-count-32", header([segment32(nsects=0xFFFFFFFF)], bits=32) + bytes(16), writable=False)
        case("segment-beyond-file", header([segment64(filesize=17)]) + bytes(16))
        case("segment-file-overflow", header([segment64(fileoff=0xFFFFFFFFFFFFFFF8)]) + bytes(16))
        case("segment-vm-overflow", header([segment64(vmaddr=0xFFFFFFFFFFFFFFF8)]) + bytes(16))
        case("section-beyond-segment", header([segment64(size=17)]) + bytes(16))
        case("section-file-before-segment", header([segment64(offset=183)]) + bytes(16))
        case("section-file-after-segment", header([segment64(offset=185)]) + bytes(16))
        case("section-relocations-truncated", header([segment64(reloff=199, nreloc=1)]) + bytes(16))
        case("wrong-segment-width", header([segment32()]) + bytes(16))
        case("invalid-after-valid-segment", header([
            segment64(nsects=0, fileoff=0, filesize=0, include_section=False),
            segment64(nsects=2)]) + bytes(16))
        fileset_command = struct.pack("<IIQQII", 0x80000035, 40, 0x1000, 72, 32, 0) + b"child\0\0\0"
        child = header([segment64(fileoff=256, offset=256)]) + bytes(16)
        fileset = header([fileset_command], filetype=12) + child
        case("valid-fileset", fileset, True)
        case("fileset-short-command", header([struct.pack("<II", 0x80000035, 8)], filetype=12))
        case("fileset-string-outside", replace_u32(fileset, 56, 40))
        case("fileset-string-in-header", replace_u32(fileset, 56, 0))
        case("fileset-no-terminator", fileset[:64] + b"abcdefgh" + fileset[72:])
        case("fileset-self-reference", replace_u32(fileset, 48, 0))
        case("fileset-child-truncated", fileset[:-1])
        case("fileset-child-invalid", fileset[:72] + bytes(32))
        nested = header([])
        for _ in range(64):
            nested = header([fileset_command], filetype=12) + nested
        case("valid-fileset-depth-limit", nested, True)
        case("fileset-too-deep", header([fileset_command], filetype=12) + nested)

        def signature_case(name, payload, mode="0", *, declared_size=None, data_offset=64):
            """使用最小合法 Mach-O 外壳，单独检查签名容器边界。"""
            size = len(payload) if declared_size is None else declared_size
            data = header([struct.pack("<IIII", 0x1D, 16, data_offset, size)], filetype=2)
            data += bytes(64 - len(data)) + payload
            path = work / name
            path.write_bytes(data)
            arguments.extend(["s" + mode, str(path)])

        blob = struct.pack(">II", 0xFADE0B01, 12) + b"data"
        valid_signature = signature([blob])
        signature_case("signature-valid-single", valid_signature, "1")
        signature_case("signature-valid-multiple", signature([blob, blob]), "1")
        signature_case("signature-valid-empty", signature([]), "1")
        signature_case("signature-valid-padding", valid_signature + bytes(16), "1")
        signature_case("signature-short-header", valid_signature, declared_size=11)
        signature_case("signature-offset-after-file", valid_signature, data_offset=0xFFFFFFF0)
        signature_case("signature-size-after-file", valid_signature, declared_size=len(valid_signature) + 1)
        signature_case("signature-outside-trimmed-slice", valid_signature, "t")
        signature_case("signature-payload-read-fails", valid_signature, "f")
        signature_case("signature-superblob-length-short", replace_be32(valid_signature, 4, 11))
        signature_case("signature-superblob-length-long", replace_be32(valid_signature, 4, len(valid_signature) + 1))
        signature_case("signature-count-too-large", replace_be32(valid_signature, 8, 0xFFFFFFFF))
        signature_case("signature-index-array-truncated", struct.pack(">III", 0xFADE0CC0, 19, 1) + bytes(7))
        signature_case("signature-index-in-header", replace_be32(valid_signature, 16, 8))
        signature_case("signature-index-in-index-array", replace_be32(valid_signature, 16, 16))
        signature_case("signature-index-after-end", replace_be32(valid_signature, 16, 0xFFFFFFFF))
        signature_case("signature-child-header-truncated", replace_be32(valid_signature, 16, len(valid_signature) - 7))
        signature_case("signature-child-length-zero", replace_be32(valid_signature, 24, 0))
        signature_case("signature-child-length-short", replace_be32(valid_signature, 24, 7))
        signature_case("signature-child-length-long", replace_be32(valid_signature, 24, 13))
        signature_case("signature-child-length-huge", replace_be32(valid_signature, 24, 0xFFFFFFFF))
        multiple = signature([blob, blob])
        signature_case("signature-second-child-invalid", replace_be32(multiple, 44, 13))
        # 编码器连续写入可变长 blob，不要求各索引为四字节对齐。
        odd_blob = struct.pack(">II", 0xFADE0B01, 9) + b"x"
        signature_case("signature-valid-unaligned-child", signature([odd_blob, blob]), "1")

        # 编译器产出的真实对象文件和可执行文件用于避免过严校验。
        source = work / "normal.c"
        source.write_text("int zero_fill[32]; int initialized = 7; int main(void) { return zero_fill[0] + initialized; }\n")
        for arch in ("arm64", "x86_64"):
            object_file = work / f"normal-{arch}.o"
            subprocess.run(["clang", "-arch", arch, "-g", "-c", str(source), "-o", str(object_file)], check=True)
            arguments.extend(["1", str(object_file)])
        executable = work / "normal-executable"
        subprocess.run(["clang", str(source), "-o", str(executable)], check=True)
        arguments.extend(["1", str(executable)])
        environment = os.environ.copy()
        # macOS 的 ASan 不提供 LeakSanitizer；仍启用地址与未定义行为检查。
        environment["ASAN_OPTIONS"] = "abort_on_error=1"
        result = subprocess.run([str(binary), str(valid_path), *arguments], env=environment)
        if result.returncode:
            raise SystemExit(f"MachO parser regression failed: {result.returncode}")


if __name__ == "__main__":
    run()
