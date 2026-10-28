//
// Created by Ylarod on 2024/3/15.
//

#include <sys/event.h>
#include <errno.h>
#import <Foundation/Foundation.h>

#include <libjailbreak/libjailbreak.h>
#include "exec_patch.h"
#include "common.h"
#include "log.h"

int kq = -1;
dispatch_queue_t gExecPatchDataQueue = nil;
NSMutableDictionary *gExecPatchArray = nil;
static uintptr_t gExecPatchGeneration = 0;

// 变更监听时重试信号中断，调用方负责在数据队列内串行执行。
static int change_exec_patch_event(struct kevent *event)
{
    int ret;
    do {
        ret = kevent(kq, event, 1, NULL, 0, NULL);
    } while (ret == -1 && errno == EINTR);
    return ret;
}

// 只消费同一代监听的记录，旧事件不能删除后来注册的进程状态。
static void handle_exec_patch_event(const struct kevent *event)
{
    pid_t pid = (pid_t)event->ident;
    dispatch_sync(gExecPatchDataQueue, ^{
        NSDictionary *record = gExecPatchArray[@(pid)];
        if (!record || [record[@"generation"] unsignedLongLongValue] != (uintptr_t)event->udata) {
            JBLogError("[execPatch] no record for process: %d", pid);
            return;
        }

        [gExecPatchArray removeObjectForKey:@(pid)];
        if(event->fflags & NOTE_EXIT)
        {
            JBLogError("kevent: unexpected process exit: %d", pid);
        }
        else if(event->fflags & NOTE_EXEC)
        {
            JBLogDebug("kevent: process exec: %d", pid);
            if(roothide_patch_proc(pid) == 0) {
                if ([record[@"resume"] boolValue]) kill(pid, SIGCONT);
            } else {
                JBLogError("[execPatch] failed to patch for process: %d", pid);
                //we hosted the spawned(SETEXEC) process so we have to deal with it if patching failed
                kill(pid, SIGQUIT); //core dump
                kill(pid, SIGKILL);
            }
        }
    });
}

// 等待一次性进程事件，将记录消费和修复操作提交到同一串行队列。
void event_handler(int kq)
{
    while(true)
    {
        struct kevent event = {0};
        int ret = kevent(kq, NULL, 0, &event, 1, NULL);
        if (ret == -1 && errno == EINTR) continue;
        assert(ret == 1);
        assert(event.filter == EVFILT_PROC);
        handle_exec_patch_event(&event);
    }
}

// 初始化进程监听和数据串行队列。
void initExecPatch() 
{
    static dispatch_queue_t queue;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        gExecPatchArray = [[NSMutableDictionary alloc] init];
        gExecPatchDataQueue = dispatch_queue_create("roothide.execpatch.data-queue", DISPATCH_QUEUE_SERIAL);

        kq = kqueue();
        assert(kq != -1);

        queue = dispatch_queue_create("roothide.execpatch.event-queue", DISPATCH_QUEUE_SERIAL);
        dispatch_async(queue, ^{
            event_handler(kq);
        });
    });
}

// 监听与记录一起发布；添加失败不保留无法收到事件的记录。
int spawnExecPatchAdd(int pid, bool resume)
{
    initExecPatch();

    __block int error = 0;
    dispatch_sync(gExecPatchDataQueue, ^{
        if([gExecPatchArray objectForKey:@(pid)] != nil) {
            JBLogError("[spawnExecPatchAdd] already has record for process: %d", pid);
        }
        // 也清理曾取消失败的内核监听，避免旧事件被重新标记为新一代。
        struct kevent previous;
        EV_SET(&previous, pid, EVFILT_PROC, EV_DELETE, 0, 0, NULL);
        int ret = change_exec_patch_event(&previous);
        int deleteError = errno;
        [gExecPatchArray removeObjectForKey:@(pid)];
        if (ret == -1 && deleteError != ENOENT) {
            error = deleteError;
            return;
        }

        uintptr_t generation = ++gExecPatchGeneration;
        if (!generation) generation = ++gExecPatchGeneration;
        struct kevent kev;
        EV_SET(&kev, pid, EVFILT_PROC, EV_ADD | EV_ENABLE | EV_ONESHOT, NOTE_EXEC|NOTE_EXIT, 0, (void *)generation);
        if (change_exec_patch_event(&kev) == -1) {
            error = errno;
            return;
        }
        gExecPatchArray[@(pid)] = @{@"resume": @(resume), @"generation": @(generation)};
    });
    if (error) {
        JBLogError("add kevent failed for pid: %d", pid);
        errno = error;
        return -1;
    }
    return 0;
}

// 取消时无论内核监听是否已消失，都释放对应记录。
int spawnExecPatchDel(int pid)
{
    initExecPatch();

    __block int ret = -1;
    __block int error = 0;
    dispatch_sync(gExecPatchDataQueue, ^{
        struct kevent kev;
        EV_SET(&kev, pid, EVFILT_PROC, EV_DELETE, 0, 0, NULL);
        if (change_exec_patch_event(&kev) == -1) error = errno;
        if([gExecPatchArray objectForKey:@(pid)] != nil) {
            [gExecPatchArray removeObjectForKey:@(pid)];
            if (!error) ret = 0;
        } else {
            JBLogError("[spawnExecPatchDel] no record for process: %d", pid);
        }
    });
    if (error) errno = error;
    return ret;
}
