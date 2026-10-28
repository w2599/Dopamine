#!/usr/bin/env python3
"""编译真实配置缓存，在普通、ASAN 或 TSAN 模式下执行回归。"""
from pathlib import Path
import argparse
import os
import subprocess
import tempfile


def main():
    """对真实缓存注入分配和解析窗口，可指定旧源码单独复现回归。"""
    parser = argparse.ArgumentParser()
    parser.add_argument("--sanitizer", choices=("none", "address", "thread"), default="none")
    parser.add_argument("--case", choices=("all", "unicode", "fork", "vfork", "atfork", "partial-vfork",
                        "initialization-fork", "initialization-vfork", "initialization-race", "initialization-failure"), default="all")
    parser.add_argument("--source", type=Path, help="缓存实现源码；用于对照旧版本")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    include = root / "BaseBin/libroothider/src"
    production = args.source.resolve() if args.source else include / "_configuration.c"
    if not production.is_file():
        raise SystemExit("Production _configuration.c is not present yet")
    compiler = os.environ.get("CC", "clang")
    flags = ["-std=gnu11", "-fblocks", "-O1", "-g", "-fno-omit-frame-pointer",
             "-I", str(include), "-Werror=implicit-function-declaration", "-Wno-deprecated-declarations"]
    if args.sanitizer != "none":
        flags += ["-fsanitize=" + args.sanitizer]
    with tempfile.TemporaryDirectory(prefix="configuration-cache-", dir=root / "worker") as temporary:
        directory = Path(temporary)
        obj, binary = directory / "configuration.o", directory / "test-configuration"
        subprocess.run([compiler, *flags, "-Dopen=cache_test_open",
                        "-Dcalloc=cache_test_calloc", "-Dstrdup=cache_test_strdup", "-Dfree=cache_test_free",
                        "-Dpthread_mutex_init=cache_test_mutex_init", "-Dpthread_mutex_destroy=cache_test_mutex_destroy",
                        "-Dxpc_create_from_plist=cache_test_parse", "-c", str(production), "-o", str(obj)], check=True)
        subprocess.run([compiler, *flags, str(root / "worker/test_configuration_cache.c"),
                        str(root / "worker/test_configuration_bool_value.m"), str(obj),
                        "-framework", "Foundation", "-o", str(binary)], check=True)
        env = os.environ.copy()
        if args.sanitizer == "address":
            env.setdefault("ASAN_OPTIONS", "detect_leaks=0:abort_on_error=1")
        if args.sanitizer == "thread":
            env.setdefault("TSAN_OPTIONS", "halt_on_error=1")
        cases = [args.case]
        if args.case == "all":
            cases += ["initialization-fork", "initialization-vfork", "initialization-race", "initialization-failure"]
        for case in cases:
            print(f"Running production cache regression: {args.sanitizer} / {case}", flush=True)
            subprocess.run([str(binary), str(directory), case], check=True, env=env, timeout=45)


if __name__ == "__main__":
    main()
