#import <Foundation/Foundation.h>
#include <stdbool.h>

// 直接用 Foundation 判断，避免测试复制生产转换算法。
bool cache_test_foundation_bool(const char *string)
{
    @autoreleasepool {
        return [[NSString stringWithUTF8String:string] boolValue];
    }
}
