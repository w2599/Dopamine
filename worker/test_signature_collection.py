#!/usr/bin/env python3
"""验证架构筛选及切片收集失败不会交付部分结果。"""
from pathlib import Path
import os
import subprocess
import sys
import tempfile
sys.dont_write_bytecode=True
from test_spawn_persona_guard import extract_function
ROOT=Path(__file__).resolve().parents[1]
PREFIX=r'''
#include <assert.h>
#include <dispatch/dispatch.h>
#include <limits.h>
#include <fcntl.h>
#include <choma/Fat.h>
#include <choma/MachO.h>
#include <choma/Host.h>
#include <choma/CodeDirectory.h>
#include <choma/FileStream.h>
static int failAt, calls, allocations, allocationFailure;
static void *mock_realloc(void *p,size_t size) { if(++allocations==allocationFailure) return NULL; return realloc(p,size); }
#define realloc mock_realloc
static int mock_host(cpu_type_t *t,cpu_subtype_t *s) { *t=CPU_TYPE_ARM64;*s=CPU_SUBTYPE_ARM64E;return 0; }
#define host_get_cpu_information mock_host
static bool string_has_prefix(const char *s,const char *p) {return !strncmp(s,p,strlen(p));}
static bool isRemovableBundlePath(const char *p) {return false;}
static bool hasTrollstoreLiteMarker(const char *p) {return false;}
static bool hasJailFoolsMarker(const char *p) {return false;}
static bool is_cdhash_trustcached(const void *h) {return false;}
static int signatureResult = 1;
static int macho_collect_adhoc_cdhash(MachO *m,void *h) {memset(h,1,20);return signatureResult;}
static int ensure_randomized_cdhash_for_slice(const char *path,uint64_t off,void *hash) {
    calls++;memset(hash,(int)off,20);return calls==failAt ? -1 : 0;
}
'''
MAIN=r'''
int main(int argc,char **argv) {
    MachO first={0},second={0};
    first.machHeader.cputype=CPU_TYPE_ARM64;first.machHeader.cpusubtype=CPU_SUBTYPE_ARM64E;first.machHeader.filetype=MH_DYLIB;
    assert(macho_is_mappable(&first));first.machHeader.filetype=MH_EXECUTE;assert(!macho_is_mappable(&first));
    first.machHeader.cpusubtype=CPU_SUBTYPE_ARM64_ALL;assert(macho_is_mappable(&first));second=first;
    first.archDescriptor.offset=1;second.archDescriptor.offset=2;
    MachO *slices[]={&first,&second};
    int fd=open(argv[1],O_CREAT|O_RDWR,0600);assert(fd>=0);
    FileStreamContext context={.fd=fd};MemoryStream stream={.context=&context};Fat fat={.stream=&stream,.slices=slices,.slicesCount=2};
    for(int mode=0;mode<6;mode++) {
        signatureResult=mode==4 ? -1 : mode==5 ? 0 : 1;
        failAt=mode==1 ? 1 : mode==2 ? 2 : 0;allocationFailure=mode==3 ? 2 : 0;calls=allocations=0;
        cdhash_t *hashes=(void *)1;uint32_t count=99;
        int result=fat_collect_untrusted_cdhashes(&fat,&hashes,&count);
        if(mode==0) {assert(result==0 && count==2 && hashes[0][0]==1 && hashes[1][0]==2);free(hashes);}
        else if(mode==5) assert(result==0 && hashes==NULL && count==0);
        else assert(result!=0 && hashes==NULL && count==0);
    }
    close(fd);cdhash_t *hashes=(void *)1;uint32_t count=99;
    assert(fat_collect_untrusted_cdhashes(&fat,&hashes,&count)!=0 && hashes==NULL && count==0);
    puts("PASS old arm64e library selection and all-or-error cdhash collection");
}
'''
def main():
    """用真实切片遍历和文件描述符运行收集函数。"""
    source=(ROOT/'BaseBin/libjailbreak/src/signatures.c').read_text()
    actual=extract_function(source,'bool macho_is_mappable(')+extract_function(source,'int fat_collect_untrusted_cdhashes(')
    with tempfile.TemporaryDirectory(prefix='signature-collection-',dir=ROOT/'worker') as tmp:
        directory=Path(tmp);(directory/'choma').symlink_to(ROOT/'BaseBin/ChOma/src',target_is_directory=True)
        harness=directory/'test.c';binary=directory/'test';harness.write_text(PREFIX+actual+MAIN)
        subprocess.run([os.environ.get('CC','clang'),'-fblocks','-fsanitize=address,undefined','-O1','-g','-Wno-deprecated-declarations','-I',str(directory),str(harness),*map(str,(ROOT/'BaseBin/ChOma/src').glob('*.c')),'-framework','CoreFoundation','-o',str(binary)],check=True)
        subprocess.run([str(binary),str(directory/'fixture')],check=True,timeout=30)
if __name__=='__main__':main()
