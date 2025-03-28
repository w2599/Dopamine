
#include <stdbool.h>

#include <libjailbreak/libjailbreak.h>
#include <libjailbreak/jbclient_xpc.h>
#include <libjailbreak/roothider.h>
#include <libjailbreak/codesign.h>

bool isJailbreakBundlePath(const char* path);

//These apps may be signed with a (fake) certificate
#define SENSITIVE_APP_LIST   @[ \
    @"com.icraze.gtatracker", \
    @"com.Alfie.TrollInstallerX", \
    @"com.opa334.Dopamine", \
    @"com.opa334.Dopamine.roothide", \
    @"com.opa334.Dopamine-roothide", \
    @"com.opa334.TrollStore", \
    @"com.zqbb.Dopamine", \
    @"com.zqbb.Dopamine.roothide", \
    @"com.zqbb.Dopamine-roothide", \
    @"cn.zqbb.TrollStore", \
    @"wiki.qaq.TrollFools", \
    @"com.netskao.dumpdecrypter", \
    @"org.coolstar.SileoStore", \
    @"com.roothide.manager", \
    @"com.roothide.patcher", \
    @"com.tigisoftware.Filza", \
    @"com.amywhile.Aemulo", \
    @"com.82flex.reveil", \
    @"com.yiming.iMemScan", \
    @"com.apibug.CheatEngine", \
]
