#!/usr/bin/env python3
"""提取生产 IPC/hookd 函数，在本机回归边界和错误恢复；不连接设备。"""
from pathlib import Path
import argparse
import os
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    """按模块运行真实源码，也支持指定旧提交复现。"""
    parser = argparse.ArgumentParser()
    parser.add_argument('--sanitizer', choices=('none', 'address', 'undefined', 'thread'), default='none')
    parser.add_argument('--case', default='all')
    parser.add_argument('--revision', help='使用 git 提交中的生产代码作对照')
    args = parser.parse_args()

    def source(path):
        """读取当前源码或指定提交，不修改仓库。"""
        if args.revision:
            return subprocess.check_output(['git', 'show', f'{args.revision}:{path}'], cwd=ROOT, text=True)
        return (ROOT / path).read_text()

    def without_includes(text):
        """保留生产函数，只移除依赖于 iOS 构建布局的 include。"""
        return re.sub(r'^#include[^\n]*\n', '', text, flags=re.M)

    header = source('BaseBin/libjailbreak/src/jbserver.h')
    ipc_types = header[header.index('typedef enum'):header.index('extern struct jbserver_impl')]
    table = source('BaseBin/launchdhook/src/jbserver/jbdomain_systemwide.c')
    table = table[table.index('struct jbserver_domain gSystemwideDomain ='):]
    handlers = set(re.findall(r'\.handler\s*=\s*(\w+)', table))
    stubs = '\n'.join(f'#define {name} test_unused' for name in handlers - {
        'jbsettings_get', 'systemwide_persona_fix', 'systemwide_trust_file'})
    ipc = source('BaseBin/libjailbreak/src/jbserver.c')
    server = source('BaseBin/hookd/src/main.c')
    server = server[:server.index('\nint main(')]
    provider = source('BaseBin/launchdhook/src/hookd_provider.c')
    mach = source('BaseBin/launchdhook/src/jbserver/jbserver_mach.c')
    mach = mach[mach.index('int jbserver_received_mach_message('):mach.index('/*int jbserver_received_complex_mach_message')]
    flags = ['-std=gnu11', '-fblocks', '-O1', '-g', '-fno-omit-frame-pointer', '-Werror=implicit-function-declaration',
             '-Wno-deprecated-declarations', '-I', str(ROOT / 'BaseBin/libjailbreak/src')]
    if args.sanitizer != 'none':
        flags += ['-fsanitize=' + args.sanitizer]
    env = os.environ.copy()
    env.setdefault('ASAN_OPTIONS', 'detect_leaks=0:abort_on_error=1')
    env.setdefault('UBSAN_OPTIONS', 'halt_on_error=1')
    env.setdefault('TSAN_OPTIONS', 'halt_on_error=1')
    with tempfile.TemporaryDirectory(prefix='ipc-hookd-', dir=ROOT / 'worker') as temporary:
        directory = Path(temporary)
        (directory / 'ipc_types.inc').write_text(ipc_types)
        (directory / 'mach_types.inc').write_text(header[header.index('#define JBSERVER_MACH_MAGIC'):header.rindex('#endif')])
        (directory / 'mach_production.inc').write_text(mach)
        (directory / 'ipc_table.inc').write_text(stubs + '\n' + table)
        (directory / 'ipc_production.inc').write_text(without_includes(ipc))
        (directory / 'hookd_production.inc').write_text(without_includes(server))
        (directory / 'provider_production.inc').write_text(('#define IPC_HOOKD_FIXED_PROVIDER 1\n' if 'gHookdStopping' in provider else '') + without_includes(provider))
        (directory / 'hookd_wire.h').write_text(source('BaseBin/libjailbreak/src/hookd.h'))
        for module in ('ipc', 'hookd', 'provider', 'mach'):
            if args.case != 'all' and not args.case.startswith(module + '-'):
                continue
            binary = directory / module
            subprocess.run(['clang', *flags, '-I', str(directory),
                            str(ROOT / f'worker/test_ipc_hookd_{module}.c'), '-lbsm', '-o', str(binary)], check=True)
            print(f'Running {module}: {args.sanitizer} / {args.case}', flush=True)
            subprocess.run([str(binary), args.case], check=True, env=env, timeout=30)


if __name__ == '__main__':
    main()
