#ifndef TROLLSTORE_LITE_BUNDLE_H
#define TROLLSTORE_LITE_BUNDLE_H
#include <stdbool.h>

// 枚举包内 Mach-O 候选文件；资源缓存只复用未变化文件的非 Mach-O 判断。
int trollstore_lite_bundle_enumerate(const char *path, bool skipNestedBundles,
                                    int (^visit)(const char *path));
#endif
