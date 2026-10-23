#import "DORuntimeConfiguration.h"
#import <libjailbreak/libjailbreak.h>
#import <sys/stat.h>

@implementation DORuntimeConfiguration

// 写入默认配置，并保持已有用户配置。
+ (NSError *)writeDefaults:(NSDictionary *)defaults name:(NSString *)name replace:(BOOL)replace
{
    NSString *path = [JBROOT_PATH(@"/var/mobile/Library/RootHide") stringByAppendingPathComponent:name];
    if (!replace && [NSFileManager.defaultManager fileExistsAtPath:path]) return nil;
    NSData *data = [NSPropertyListSerialization dataWithPropertyList:defaults format:NSPropertyListXMLFormat_v1_0 options:0 error:nil];
    NSError *error = nil;
    if (![data writeToFile:path options:NSDataWritingAtomic error:&error]) return error;
    return nil;
}

// 准备注入白名单和每进程内存额度，供后续启动流程读取。
+ (NSError *)prepare
{
    NSString *root = JBROOT_PATH(@"/var/mobile/Library/RootHide");
    NSError *error = nil;
    if (![NSFileManager.defaultManager createDirectoryAtPath:root withIntermediateDirectories:YES attributes:nil error:&error]) return error;
    NSArray *defaultItems = @[
        @"/.jbroot", @"/xpcproxy",
        @"/amfid", @"/cfprefsd", @"/lsd", @"/watchdogd",
        @"/SpringBoard", @"/Preferences",
        @"/Dopamine",
        @"/SafariViewService",
        @"/iconservicesagent",
        @"/lockdownd",
        @"/MobileStorageMounter",
        @"/mobileassetd", @"/MobileGestaltHelper", @"/useractivityd", @"/transitd"
    ];
    NSMutableDictionary *systemWhitelist = [NSMutableDictionary dictionary];
    for (NSString *item in defaultItems) systemWhitelist[item] = @YES;
    error = [self writeDefaults:systemWhitelist name:@"cn.zqbb.inject.system.plist" replace:YES];
    if (error) return error;
    error = [self writeDefaults:@{@"QQ": @YES, @"WeChat": @YES, @"Runner": @YES, @"AppStore": @YES}
                          name:@"cn.zqbb.inject.wantsblacklist.plist" replace:NO];
    if (error) return error;
    error = [self writeDefaults:@{@"/SpringBoard": @1024, @"/xxtouch": @48, @"/thermalmonitord": @16}
                          name:@"cn.zqbb.jetsam.addend.plist" replace:NO];
    if (error) return error;

    // 配置归 mobile 所有，跳过符号链接。
    NSArray *paths = [[NSFileManager.defaultManager subpathsAtPath:root] arrayByAddingObject:@""];
    NSDictionary *attributes = @{NSFileOwnerAccountID: @501, NSFileGroupOwnerAccountID: @501, NSFilePosixPermissions: @0755};
    for (NSString *relativePath in paths) {
        NSString *path = [root stringByAppendingPathComponent:relativePath];
        NSDictionary *existing = [NSFileManager.defaultManager attributesOfItemAtPath:path error:&error];
        if (!existing) return error;
        if ([existing[NSFileType] isEqualToString:NSFileTypeSymbolicLink]) continue;
        if (![NSFileManager.defaultManager setAttributes:attributes ofItemAtPath:path error:&error]) return error;
    }
    return nil;
}

// 首次建立越狱标记，之后让已安装的挂载服务恢复用户挂载。
+ (NSError *)restoreCustomMounts
{
    NSString *mountRoot = JBROOT_PATH(@"/mnt");
    NSError *error = nil;
    if (![NSFileManager.defaultManager createDirectoryAtPath:mountRoot withIntermediateDirectories:YES attributes:nil error:&error]) return error;
    NSString *flagPath = [mountRoot stringByAppendingPathComponent:@".zqbbJailbreak"];
    if (![NSFileManager.defaultManager fileExistsAtPath:flagPath]) {
        if (![[NSData data] writeToFile:flagPath options:NSDataWritingAtomic error:&error]) return error;
    }
    else if (access(JBROOT_PATH("/usr/bin/HelloMntDaemon"), F_OK) == 0) {
        int status = exec_cmd_trusted(JBROOT_PATH("/usr/bin/HelloMntDaemon"), "remountAll", NULL);
        if (status != 0) return [NSError errorWithDomain:@"DORuntimeConfiguration" code:status userInfo:@{NSLocalizedDescriptionKey: @"HelloMntDaemon remountAll failed"}];
    }
    return nil;
}
@end
