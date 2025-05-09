#import <Foundation/Foundation.h>

#include "../libjailbreak.h"
#include "common.h"


#define APP_PATH_PREFIX "/private/var/containers/Bundle/Application/"
#define NULL_UUID "00000000-0000-0000-0000-000000000000"

NSString *getAppBundlePathFromSpawnPath(const char *path) {
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
NSString *getAppIdentifierFromPath(const char *path) {
    if (!path) return nil;

    NSString *bundlePath = getAppBundlePathFromSpawnPath(path);
    if (!bundlePath) return nil;

    NSDictionary *appInfo = [NSDictionary dictionaryWithContentsOfFile:[NSString stringWithFormat:@"%@/Info.plist", bundlePath]];
    if (!appInfo) return nil;

    NSString *identifier = appInfo[@"CFBundleIdentifier"];
    if (!identifier) return nil;

    return identifier;
}

NSArray* builtinApps = @[
    @"com.opa334.Dopamine-roothide",
    @"com.zqbb.Dopamine-roothide"
];

bool isBlacklistedApp(const char* identifier)
{
    if(!identifier) return false;

    if([builtinApps containsObject:@(identifier)]) return false;

    NSString* configFilePath = JBROOT_PATH(@"/var/mobile/Library/RootHide/RootHideConfig.plist");
    NSDictionary* roothideConfig = [NSDictionary dictionaryWithContentsOfFile:configFilePath];
    if(!roothideConfig) return false;

    NSDictionary* appconfig = roothideConfig[@"appconfig"];
    if(!appconfig) return false;

    NSNumber* blacklisted = appconfig[@(identifier)];
    if(!blacklisted) return false;

    return blacklisted.boolValue;
}

bool isBlacklistedPath_orig(const char* path)
{
    // if(!path) return false;
    NSString* identifier = getAppIdentifierFromPath(path);
    // if(!identifier) return false;
    return isBlacklistedApp(identifier.UTF8String);
}

bool wantInject(const char *execName, const char *injectPath);
bool isBlacklistedExec(const char *path, const char *injectPath) {
    const char *exec = strrchr(path, '/');
    if (!exec) return 1;

    if (!strcmp(exec + 1, "QQ") || !strcmp(exec + 1, "WeChat") || !strcmp(exec + 1, "Runner")){
        if (isBlacklistedPath_orig(path)) return 1;
    }

    if (wantInject(exec + 1, injectPath))
        return 0; // 在白名单则注入

    return 1;
}

bool isWhiteList(const char *path, const char *injectSystemPath);

bool isBlacklistedPath(const char* path)
{
    if(!path) return 0;
    const char *injectPath = JBROOT_PATH("/var/mobile/Library/RootHide/cn.zqbb.inject.plist");
    const char *injectSystemPath = JBROOT_PATH("/var/mobile/Library/RootHide/cn.zqbb.inject.system.plist");
    if (access(injectPath, F_OK) == 0){
        if (!strcmp(path, "/sbin/launchd")) return 0;
        if (isWhiteList(path,injectSystemPath)) return 0;
        return isBlacklistedExec(path, injectPath);
    }
    return isBlacklistedPath_orig(path);
}
