#import <Foundation/Foundation.h>

#include <libjailbreak/libjailbreak.h>
#include "common.h"


#define APP_PATH_PREFIX "/private/var/containers/Bundle/Application/"
#define NULL_UUID "00000000-0000-0000-0000-000000000000"

NSString *getAppBundlePathFromSpawnPath(const char *path)
{
    if (!path) return nil;

    char abspath[PATH_MAX];
    if (!realpath(path, abspath)) return nil;

    if (strncmp(abspath, APP_PATH_PREFIX, sizeof(APP_PATH_PREFIX) - 1) != 0)
        return nil;

    char *p1 = abspath + sizeof(APP_PATH_PREFIX) - 1;
    char *p2 = strchr(p1, '/');
    if (!p2) return nil;

    //is normal app or jailbroken app/daemon?
    if ((p2 - p1) != (sizeof(NULL_UUID) - 1))
        return nil;

    char *p = strstr(p2, ".app/");
    if (!p) return nil;

    p[sizeof(".app/") - 1] = '\0';

    return [NSString stringWithUTF8String:abspath];
}

// get main bundle identifier of app for (PlugIns's) executable path
NSString *getAppIdentifierFromPath(const char *path)
{
    if (!path) return nil;

    NSString *bundlePath = getAppBundlePathFromSpawnPath(path);
    if (!bundlePath) return nil;

    NSDictionary *appInfo = [NSDictionary dictionaryWithContentsOfFile:[NSString stringWithFormat:@"%@/Info.plist", bundlePath]];
    if (!appInfo) return nil;

    NSString *identifier = appInfo[@"CFBundleIdentifier"];
    if (!identifier) return nil;

    return identifier;
}

NSSet* builtinApps()
{
    static NSSet* apps = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        JBLogDebug("Initializing builtin apps set");
        apps = [NSSet setWithObjects:@"com.opa334.Dopamine-roothide", nil];
        NSString* customBundleId = [NSString stringWithContentsOfFile:JBROOT_PATH(@"/basebin/.AppIdentifier") encoding:NSUTF8StringEncoding error:nil];
        if(customBundleId && customBundleId.length > 0) {
            JBLogDebug("Added custom bundle identifier to builtin apps: %s", customBundleId.UTF8String);
            apps = [apps setByAddingObject:customBundleId];
        }
    });
    return apps;
}

bool isBlacklistedApp(const char* identifier)
{
    if(!identifier) return false;

    if([builtinApps() containsObject:@(identifier)]) return false;

    NSString* configFilePath = JBROOT_PATH(@"/var/mobile/Library/RootHide/RootHideConfig.plist");
    NSDictionary* roothideConfig = [NSDictionary dictionaryWithContentsOfFile:configFilePath];
    if(!roothideConfig) return false;

    NSDictionary* appconfig = roothideConfig[@"appconfig"];
    if(!appconfig) return false;

    NSNumber* blacklisted = appconfig[@(identifier)];
    if(!blacklisted) return false;

    return blacklisted.boolValue;
}

// 按原有应用标识黑名单判断。
static bool isBlacklistedPath_orig(const char* path)
{
    if(!path) return false;
    NSString* identifier = getAppIdentifierFromPath(path);
    if(!identifier) return false;
    return isBlacklistedApp(identifier.UTF8String);
}

static const char *injectPlistPath = NULL;
static const char *injectSystemPlistPath = NULL;

bool zqbb_wantsInject(const char *execName, const char *injectPath);
// 查询需要同时遵循原黑名单的进程。
static BOOL zqbb_wantsBlacklist(NSString *execName) {
    if(!execName) return NO;

    NSString* configFilePath = JBROOT_PATH(@"/var/mobile/Library/RootHide/cn.zqbb.inject.wantsblacklist.plist");
    NSDictionary* wantsBlacklistConfig = [NSDictionary dictionaryWithContentsOfFile:configFilePath];
    if(!wantsBlacklistConfig) return NO;

    return [wantsBlacklistConfig[execName] boolValue];
}

// 按可执行文件名判断白名单，并应用指定进程的黑名单覆盖。
static bool zqbb_isBlacklistedExec(const char *path, const char *injectPath) {
    const char *exec = strrchr(path, '/');
    if (!exec) return true;
    exec++;

    if (zqbb_wantsBlacklist([NSString stringWithUTF8String:exec])) {
        if (isBlacklistedPath_orig(path)) return true;
    }

    if (zqbb_wantsInject(exec, injectPath))
        return false; // 在白名单则注入

    return true;
}

bool zqbb_isWhiteListForSystem(const char *path, const char *injectSystemPath);
// 存在用户白名单时切换模式，否则保留原有黑名单逻辑。
bool isBlacklistedPath(const char* path) {
    if(!path) return false;

    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        injectPlistPath = strdup(JBROOT_PATH("/var/mobile/Library/RootHide/cn.zqbb.inject.plist"));
        injectSystemPlistPath = strdup(JBROOT_PATH("/var/mobile/Library/RootHide/cn.zqbb.inject.system.plist"));
    });
    if (!injectPlistPath) return isBlacklistedPath_orig(path);

    if (access(injectPlistPath, F_OK) == 0){
        if (!strcmp(path, "/sbin/launchd")) return false;
        if (zqbb_isWhiteListForSystem(path, injectSystemPlistPath)) return false;
        return zqbb_isBlacklistedExec(path, injectPlistPath);
    }
    return isBlacklistedPath_orig(path);
}
