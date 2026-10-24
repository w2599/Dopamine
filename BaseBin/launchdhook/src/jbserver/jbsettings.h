#include <xpc/xpc.h>

int jbsettings_get(const char *key, xpc_object_t *valueOut);
int jbsettings_set(const char *key, xpc_object_t value);

// 读取 TrollStoreLite 修复开关，启动流程按本次快照处理。
bool trollstore_lite_fix_enabled(void);
