#!/usr/bin/env python3
"""真实 ChOma 文件读写回归：签名预检、失败回滚及半完成文件重试。"""
from pathlib import Path
import os
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
PREFIX=r'''
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <sys/stat.h>
#include <unistd.h>
#include <mach-o/dyld.h>
#include <choma/Fat.h>
#include <choma/MachO.h>
#include <choma/Host.h>
#include <choma/MachOByteOrder.h>
#include <choma/CodeDirectory.h>
#define JBLogDebug(...) ((void)0)
#define JBLogError(...) ((void)0)
#define jbinfo(x) UINT64_C(0x1234567812345678)
#define ksymbol(x) 0
#define CS_ADHOC 2
static int calls, failAt, partial, persistent;
// 仅在写入边界注入 I/O 错误，解析和文件操作使用真实实现。
static int write_probe(MemoryStream *stream,uint64_t off,size_t size,const void *data) {
    calls++;
    if (failAt && (calls==failAt || (persistent && calls>=failAt))) {
        if(partial && calls==failAt) assert(memory_stream_write(stream,off,size/2,data)==0);
        return -1;
    }
    return memory_stream_write(stream,off,size,data);
}
#define memory_stream_write write_probe
static bool isRemovableBundlePath(const char *p) { return false; }
static bool hasTrollstoreLiteMarker(const char *p) { return false; }
static bool hasJailFoolsMarker(const char *p) { return false; }
bool csd_superblob_is_adhoc_signed(CS_DecodedSuperBlob *blob) { return true; }
int ensure_randomized_cdhash_for_slice(const char *,uint64_t,void *);
'''
MAIN=r'''
#undef memory_stream_write
#define PAGE 4096
#define SECTION_OFFSET (sizeof(struct mach_header_64)+sizeof(struct segment_command_64))
#define BLOB_OFFSET (PAGE+sizeof(CS_SuperBlob)+sizeof(CS_BlobIndex))
static size_t fixture(uint8_t *bytes, int hashType) {
    memset(bytes,0,8192);
    uint32_t hashSize=hashType==CS_HASHTYPE_SHA384_384 ? 48 : 32;
    uint32_t directorySize=sizeof(CS_CodeDirectory)+8+hashSize;
    uint32_t signatureSize=sizeof(CS_SuperBlob)+sizeof(CS_BlobIndex)+directorySize;
    struct mach_header_64 *header=(void *)bytes;
    *header=(struct mach_header_64){.magic=MH_MAGIC_64,.cputype=CPU_TYPE_ARM64,.cpusubtype=CPU_SUBTYPE_ARM64_ALL,.filetype=MH_EXECUTE,.ncmds=2,.sizeofcmds=sizeof(struct segment_command_64)+sizeof(struct section_64)+sizeof(struct linkedit_data_command)};
    struct segment_command_64 *segment=(void *)(bytes+sizeof(*header));
    *segment=(struct segment_command_64){.cmd=LC_SEGMENT_64,.cmdsize=sizeof(*segment)+sizeof(struct section_64),.vmaddr=0x100000000,.vmsize=PAGE,.filesize=PAGE,.maxprot=5,.initprot=5,.nsects=1};
    strcpy(segment->segname,"__TEXT");
    struct section_64 *section=(void *)(bytes+SECTION_OFFSET);
    strcpy(section->segname,"__TEXT");strcpy(section->sectname,"__text");section->addr=segment->vmaddr+256;section->offset=256;section->size=16;
    struct linkedit_data_command *signature=(void *)((uint8_t *)segment+segment->cmdsize);
    *signature=(struct linkedit_data_command){.cmd=LC_CODE_SIGNATURE,.cmdsize=sizeof(*signature),.dataoff=PAGE,.datasize=signatureSize};
    CS_SuperBlob *super=(void *)(bytes+PAGE);
    super->magic=HOST_TO_BIG(CSMAGIC_EMBEDDED_SIGNATURE);super->length=HOST_TO_BIG(signatureSize);super->count=HOST_TO_BIG(1);
    super->index[0]=(CS_BlobIndex){.type=HOST_TO_BIG(CSSLOT_CODEDIRECTORY),.offset=HOST_TO_BIG((uint32_t)(sizeof(*super)+sizeof(CS_BlobIndex)))};
    CS_CodeDirectory directory={.magic=CSMAGIC_CODEDIRECTORY,.length=directorySize,.version=0x20200,.flags=CS_ADHOC,.hashOffset=sizeof(CS_CodeDirectory)+8,.identOffset=sizeof(CS_CodeDirectory),.nCodeSlots=1,.codeLimit=PAGE,.hashSize=hashSize,.hashType=hashType,.pageSize=12};
    CODE_DIRECTORY_APPLY_BYTE_ORDER(&directory,HOST_TO_BIG_APPLIER);
    memcpy(bytes+BLOB_OFFSET,&directory,sizeof(directory));strcpy((char *)bytes+BLOB_OFFSET+sizeof(directory),"test");
    return PAGE+signatureSize;
}
// 保存和读取完整文件，用字节级比较检查失败路径没有留下半次更新。
static void save(const char *path,const uint8_t *data,size_t size) { FILE *f=fopen(path,"wb");assert(f);assert(fwrite(data,1,size,f)==size);assert(fclose(f)==0); }
static void load(const char *path,uint8_t *data,size_t size) { FILE *f=fopen(path,"rb");assert(f);assert(fread(data,1,size,f)==size);fclose(f); }
static void verify(const uint8_t *bytes,int type) {
    uint8_t hash[48]; if(type==CS_HASHTYPE_SHA384_384) CC_SHA384(bytes,PAGE,hash); else CC_SHA256(bytes,PAGE,hash);
    assert(!memcmp(hash,bytes+BLOB_OFFSET+sizeof(CS_CodeDirectory)+8,type==CS_HASHTYPE_SHA384_384 ? 48 : 32));
    uint64_t marker;memcpy(&marker,bytes+SECTION_OFFSET+offsetof(struct section_64,segname)+8,8);assert(marker==jbinfo(jbrand));
}
static int descriptor_count(void) { int count=0;for(int fd=0;fd<256;fd++) if(fcntl(fd,F_GETFD)>=0) count++;return count; }
int main(int argc,char **argv) {
    uint8_t original[8192],after[8192],hash[20];
    for(int mode=0;mode<8;mode++) {
        int type=mode==7 ? CS_HASHTYPE_SHA384_384 : CS_HASHTYPE_SHA256_256;
        size_t size=fixture(original,type);
        if(mode==6) {uint64_t marker=jbinfo(jbrand);memcpy(original+SECTION_OFFSET+offsetof(struct section_64,segname)+8,&marker,8);}
        save(argv[1],original,size);calls=0;failAt=mode>=1 && mode<=5 ? (mode==1 || mode==3 || mode==5 ? 1 : 2) : 0;
        partial=mode>=3 && mode<=5;persistent=mode==5;
        int result=ensure_randomized_cdhash_for_slice(argv[1],0,hash);
        if(failAt) {
            assert(result!=0);load(argv[1],after,size);
            if(!persistent) assert(!memcmp(original,after,size));
            failAt=partial=persistent=0;calls=0;assert(ensure_randomized_cdhash_for_slice(argv[1],0,hash)==0);
        } else assert(result==0);
        load(argv[1],after,size);verify(after,type);
        calls=0;assert(ensure_randomized_cdhash_for_slice(argv[1],0,hash)==0);assert(calls==0);
    }
    for(int mode=0;mode<3;mode++) {
        size_t size=fixture(original,CS_HASHTYPE_SHA256_256);
        struct linkedit_data_command *signature=(void *)(original+SECTION_OFFSET+sizeof(struct section_64));
        if(mode<2) signature->datasize=mode==0 ? 4 : 8; else signature->dataoff=(uint32_t)size-4;
        save(argv[1],original,size);calls=0;assert(ensure_randomized_cdhash_for_slice(argv[1],0,hash)!=0);assert(calls==0);
    }
    save(argv[1],(const uint8_t *)"not a mach-o",12);
    int count=descriptor_count();for(int i=0;i<20;i++) assert(fat_init_for_writing(argv[1])==NULL);assert(descriptor_count()==count);
    int savedInput=dup(STDIN_FILENO);close(STDIN_FILENO);
    assert(fat_init_for_writing(argv[1])==NULL);assert(fcntl(STDIN_FILENO,F_GETFD)<0);
    if(savedInput>=0) {assert(dup2(savedInput,STDIN_FILENO)==STDIN_FILENO);close(savedInput);}
    puts("PASS signature recovery, SHA384, truncated signatures, stream cleanup including fd 0");
}
'''

def main():
    """链接仓库实际解析库并在临时文件上执行，不访问设备。"""
    source=(ROOT/'BaseBin/libroothider/src/recdhash.m').read_text()
    source='\n'.join(line for line in source.splitlines() if not line.startswith(('#include','#import')))
    with tempfile.TemporaryDirectory(prefix='signature-recovery-',dir=ROOT/'worker') as tmp:
        directory=Path(tmp);(directory/'choma').symlink_to(ROOT/'BaseBin/ChOma/src',target_is_directory=True)
        harness=directory/'test.m';binary=directory/'test';harness.write_text(PREFIX+source+MAIN)
        command=[os.environ.get('CC','clang'),'-fblocks','-fsanitize=address,undefined','-O1','-g','-Wno-deprecated-declarations','-I',str(directory),str(harness),*map(str,(ROOT/'BaseBin/ChOma/src').glob('*.c')),'-framework','CoreFoundation','-o',str(binary)]
        subprocess.run(command,check=True)
        subprocess.run([str(binary),str(directory/'fixture')],check=True,timeout=30,env={**os.environ,'ASAN_OPTIONS':'detect_leaks=0'})
if __name__=='__main__':main()
