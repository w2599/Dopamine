#!/usr/bin/env python3
"""使用生产函数验证进程写入、参数缓冲边界和解压失败。"""
from pathlib import Path
import os
import subprocess
import sys
import tarfile
import tempfile
sys.dont_write_bytecode = True
from test_spawn_persona_guard import extract_function
ROOT = Path(__file__).resolve().parents[1]
CC = os.environ.get('CC', 'clang')

def run(directory, name, source, flags=(), args=()):
    """编译实际函数与受控外部依赖，执行后由临时目录统一清理。"""
    path, binary = directory / (name + '.m'), directory / name
    path.write_text(source)
    subprocess.run([CC, '-fobjc-arc', '-fblocks', '-O1', '-g', '-fsanitize=address,undefined',
                    '-Wno-deprecated-declarations', '-Wno-incompatible-pointer-types', str(path),
                    '-o', str(binary), *flags], check=True)
    subprocess.run([str(binary), *map(str,args)], check=True, timeout=30,
                   env={**os.environ,'ASAN_OPTIONS':'detect_leaks=0'})

KILL = r'''
#include <sys/sysctl.h>
#include <sys/proc.h>
#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int mode, killed;
static int mock_sysctl(int *m, unsigned n, void *out, size_t *size, void *in, size_t insize) {
    if (m[1] == KERN_ARGMAX) { *(int *)out = 4096; return 0; }
    if (m[1] == KERN_PROC) {
        *size = sizeof(struct kinfo_proc);
        if (out) { memset(out,0,*size); ((struct kinfo_proc *)out)->kp_proc.p_pid = 123; }
        return 0;
    }
    assert(m[1] == KERN_PROCARGS2 && *size == 4096);
    memset(out, 'A', 2048);
    *size = mode == 2 ? 2 : 2048;
    if (mode == 0) strcpy((char *)out + sizeof(int), "/test/target");
    return 0;
}
static int mock_kill(pid_t pid, int signal) { assert(pid == 123); killed++; return 0; }
#define sysctl mock_sysctl
#define kill mock_kill
'''
KILL_MAIN = r'''
int main(void) {
    for(mode=0; mode<3; mode++) { killed=0; killall("/test/target",SIGTERM); assert(killed == (mode==0)); }
    puts("PASS killall long arguments, unterminated path, truncated result");
}
'''
ARCHIVE = r'''
#include <archive.h>
#include <archive_entry.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <assert.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>
static int inject;
static int mock_header(struct archive *a, struct archive_entry *e) {
    if (inject) return ARCHIVE_FATAL;
    return archive_write_header(a,e);
}
#define archive_write_header mock_header
'''
ARCHIVE_MAIN = r'''
int main(int argc, char **argv) {
    assert(libarchive_unarchive(argv[1],argv[2]) == 0);
    inject=1; assert(libarchive_unarchive(argv[1],argv[3]) != 0);
    inject=0; assert(libarchive_unarchive(argv[1],argv[4]) == 0);
    puts("PASS archive extraction, fatal header propagation and destination alias");
}
'''
PRIMITIVE = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
static int writes;
static uint64_t proc_task(uint64_t proc) {assert(proc==10);return 20;}
static uint64_t kread_ptr(uint64_t addr) {assert(addr==21 || addr==31);return addr==21 ? 30 : 40;}
static uint64_t kread64(uint64_t addr) {assert(addr==41);return 50;}
#define koffsetof(type,field) 1
static int vwritebuf(uint64_t table,const void *address,const void *data,size_t length) {
    assert(table==50 && address==(void *)60 && *(const int *)data==7 && length==sizeof(int));writes++;return -7;
}
'''

def main():
    """执行三个独立的生产代码回归。"""
    util=(ROOT/'BaseBin/libjailbreak/src/util.c').read_text()
    with tempfile.TemporaryDirectory(prefix='runtime-utilities-',dir=ROOT/'worker') as temporary:
        directory=Path(temporary)
        primitive=(ROOT/'BaseBin/libjailbreak/src/primitives.c').read_text()
        run(directory,'primitive',PRIMITIVE+extract_function(primitive,'int proc_vwritebuf(')+'\nint main(void) {int value=7;assert(proc_vwritebuf(10,(void *)60,&value,sizeof(value))==-7);assert(writes==1);puts("PASS process virtual write dispatch");}')
        run(directory,'killall',KILL+extract_function(util,'void killall(')+KILL_MAIN)
        fixture=directory/'files';fixture.mkdir();(fixture/'data').write_text('data')
        archive=directory/'input.tar'
        with tarfile.open(archive,'w') as output: output.add(fixture/'data',arcname='basebin/data')
        (directory/'real').mkdir();(directory/'alias').symlink_to(directory/'real',target_is_directory=True)
        run(directory,'archive',ARCHIVE+extract_function(util,'static int\ncopy_data(')+extract_function(util,'static int prepare_extraction_path(')+extract_function(util,'int libarchive_unarchive(')+ARCHIVE_MAIN,['-I',str(ROOT/'BaseBin/_external/include/libarchive'),'-larchive'],[archive,directory/'out',directory/'failed',directory/'alias/out'])
        assert (directory/'out/basebin/data').read_text()=='data'
        assert (directory/'alias/out/basebin/data').read_text()=='data'
if __name__=='__main__': main()
