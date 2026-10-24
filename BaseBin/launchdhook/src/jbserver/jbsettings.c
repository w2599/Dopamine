#include "jbsettings.h"
#include <libjailbreak/info.h>

// 默认开启；原子读取避免设置线程与进程启动线程并发访问。
bool trollstore_lite_fix_enabled(void)
{
	return !__atomic_load_n(&gSystemInfo.jailbreakSettings.trollStoreLiteFixDisabled, __ATOMIC_RELAXED);
}

int jbsettings_get(const char *key, xpc_object_t *valueOut)
{
	if (!key)	return -1;

	if (!strcmp(key, "markAppsAsDebugged")) {
		*valueOut = xpc_bool_create(jbsetting(markAppsAsDebugged));
		return 0;
	}
	else if (!strcmp(key, "trollStoreLiteFixEnabled")) {
		*valueOut = xpc_bool_create(trollstore_lite_fix_enabled());
		return 0;
	}
	else if (!strcmp(key, "jetsamMultiplier")) {
		*valueOut = xpc_double_create(jbsetting(jetsamMultiplier));
		return 0;
	}
	return -1;
}

int jbsettings_set(const char *key, xpc_object_t value)
{
	if (!strcmp(key, "markAppsAsDebugged") && xpc_get_type(value) == XPC_TYPE_BOOL) {
		gSystemInfo.jailbreakSettings.markAppsAsDebugged = xpc_bool_get_value(value);
		return 0;
	}
	else if (!strcmp(key, "trollStoreLiteFixEnabled") && xpc_get_type(value) == XPC_TYPE_BOOL) {
		__atomic_store_n(&gSystemInfo.jailbreakSettings.trollStoreLiteFixDisabled, !xpc_bool_get_value(value), __ATOMIC_RELAXED);
		return 0;
	}
	else if (!strcmp(key, "jetsamMultiplier") && xpc_get_type(value) == XPC_TYPE_DOUBLE) {
		gSystemInfo.jailbreakSettings.jetsamMultiplier = xpc_double_get_value(value);
		return 0;
	}
	return -1;
}
