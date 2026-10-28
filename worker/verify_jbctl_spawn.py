#!/usr/bin/env python3
"""提取生产 jbctl 启动方法，在本机注入系统调用错误并验证资源清理。"""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / 'Application/Dopamine/Jailbreak/DOEnvironmentManager.m').read_text()
start = source.index('- (int)spawnJbctlAsRootWithArgs:')
method = source[start:source.index('\n- (int)runTrollStoreAction:', start)]

prefix = r'''#import <Foundation/Foundation.h>
#import <spawn.h>
#import <signal.h>
#import <unistd.h>
#import <errno.h>
#import <stdbool.h>
extern char **environ;
static int fault, spawned, waited, signaled, closed, actionsDestroyed, attrsDestroyed;
// 注入文件操作初始化错误。
static int fake_actions_init(posix_spawn_file_actions_t *a) { if(fault==1) return EINVAL; *a=(void*)1; return 0; }
// 注入启动属性初始化错误。
static int fake_attr_init(posix_spawnattr_t *a) { if(fault==2) return ENOMEM; *a=(void*)1; return 0; }
// 记录文件操作资源释放。
static int fake_actions_destroy(posix_spawn_file_actions_t *a) { actionsDestroyed++; return 0; }
// 记录启动属性资源释放。
static int fake_attr_destroy(posix_spawnattr_t *a) { attrsDestroyed++; return 0; }
// 注入文件描述符耗尽错误。
static int fake_pipe(int p[2]) { if(fault==3) { errno=EMFILE; return -1; } p[0]=71; p[1]=72; return 0; }
// 注入管道传递设置错误。
static int fake_dup2(posix_spawn_file_actions_t *a,int fd,int target) { return fault==4 ? EBADF : 0; }
// 注入旧版挂起标志设置错误。
static int fake_flags(posix_spawnattr_t *a,short flags) { return fault==5 ? EINVAL : 0; }
// 模拟成功、创建失败和无效 PID，检查参数终止符。
static int fake_spawn(pid_t *p,const char *path,const posix_spawn_file_actions_t *a,const posix_spawnattr_t *b,char *const argv[],char *const env[]) {
 spawned++;
 if(strcmp(argv[0],"/fake/jbctl") || strcmp(argv[1],"respring")) abort();
 if(argv[2] && (strcmp(argv[2],"--waitfor") || strcmp(argv[3],"3") || argv[4])) abort();
 if(fault==6) return ENOENT;
 if(fault==7) { *p=0; return EACCES; }
 *p=fault==8 ? 0 : 42; return 0;
}
// 禁止向无效 PID 发信号。
static int fake_kill(pid_t p,int sig) { signaled++; if(p!=42 || sig!=SIGCONT) abort(); return 0; }
// 禁止等待无效或无关 PID。
static int fake_wait(pid_t p) { waited++; if(p!=42) abort(); return 0x1200; }
// 检查只关闭已经创建的描述符。
static int fake_close(int fd) { if(fd!=71 && fd!=72) abort(); closed++; return 0; }
// 检查握手写入目标。
static ssize_t fake_write(int fd,const void *buf,size_t size) { if(fd!=72) abort(); return size; }
#define JBROOT_PATH(x) "/fake/jbctl"
#define posix_spawn_file_actions_init fake_actions_init
#define posix_spawnattr_init fake_attr_init
#define posix_spawn_file_actions_destroy fake_actions_destroy
#define posix_spawnattr_destroy fake_attr_destroy
#define posix_spawn_file_actions_adddup2 fake_dup2
#define posix_spawnattr_setflags fake_flags
#define posix_spawn fake_spawn
#define pipe fake_pipe
#define kill fake_kill
#define cmd_wait_for_exit fake_wait
#define close fake_close
#define write fake_write
@interface SpawnHarness : NSObject
@property(copy) NSString *jailbrokenVersion;
- (void)runAsRoot:(void (^)(void))block;
- (void)runUnsandboxed:(void (^)(void))block;
- (int)spawnJbctlAsRootWithArgs:(NSArray *)args;
@end
@implementation SpawnHarness
// 模拟临时 root 授权被拒绝。
- (void)runAsRoot:(void (^)(void))block { if(fault!=9) block(); }
// 同步执行需要离开沙盒的区间。
- (void)runUnsandboxed:(void (^)(void))block { block(); }
'''
suffix = r'''
@end
// 对比错误码、进程操作和资源释放计数。
static void runCase(const char *name,int selectedFault,BOOL legacy,int expected,int expectedSpawn,int expectedSignal,int expectedWait,int expectedClose,int expectedActions,int expectedAttrs) {
 fault=selectedFault; spawned=waited=signaled=closed=actionsDestroyed=attrsDestroyed=0;
 SpawnHarness *h=[SpawnHarness new]; h.jailbrokenVersion=legacy ? @"3.0.4" : @"3.0.5";
 int r=[h spawnJbctlAsRootWithArgs:@[@"respring"]];
 if(r!=expected || spawned!=expectedSpawn || signaled!=expectedSignal || waited!=expectedWait || closed!=expectedClose || actionsDestroyed!=expectedActions || attrsDestroyed!=expectedAttrs) {
 fprintf(stderr,"FAIL %s: r=%d spawn=%d signal=%d wait=%d close=%d actions=%d attr=%d\n",name,r,spawned,signaled,waited,closed,actionsDestroyed,attrsDestroyed); exit(1);
 }
 printf("PASS %s\n",name);
}
// 运行创建成功和各初始化失败分支。
int main(void) { @autoreleasepool {
 runCase("modern success",0,NO,0x1200,1,0,1,2,1,1);
 runCase("actions init error",1,NO,EINVAL,0,0,0,0,0,0);
 runCase("attr init error",2,NO,ENOMEM,0,0,0,0,1,0);
 runCase("pipe EMFILE",3,NO,EMFILE,0,0,0,0,1,1);
 runCase("dup2 setup error",4,NO,EBADF,0,0,0,2,1,1);
 runCase("legacy flag error",5,YES,EINVAL,0,0,0,0,1,1);
 runCase("spawn ENOENT",6,NO,ENOENT,1,0,0,2,1,1);
 runCase("spawn EACCES with pid zero",7,YES,EACCES,1,0,0,0,1,1);
 runCase("invalid successful pid",8,NO,ECHILD,1,0,0,2,1,1);
 runCase("root block skipped",9,NO,EPERM,0,0,0,2,1,1);
 runCase("legacy success",0,YES,0x1200,1,1,1,0,1,1);
} return 0; }
'''

with tempfile.TemporaryDirectory(prefix='jbctl-spawn-check-', dir=ROOT / 'worker') as temporary:
    temporary = Path(temporary)
    harness = temporary / 'harness.m'
    binary = temporary / 'harness'
    harness.write_text(prefix + '// 测试从当前生产文件提取的启动方法。\n' + method + suffix)
    subprocess.run([
        'xcrun', 'clang', '-fobjc-arc', '-fblocks', '-Wall', '-Wextra', '-Werror',
        '-Wno-unused-parameter', '-Wno-unused-variable', '-framework', 'Foundation',
        str(harness), '-o', str(binary),
    ], check=True)
    subprocess.run([str(binary)], check=True)
