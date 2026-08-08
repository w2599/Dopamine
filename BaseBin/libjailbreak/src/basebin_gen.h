#ifndef __BASEBIN_GEN_H
#define __BASEBIN_GEN_H

#include <stdbool.h>

NSString *dyldhook_dylib_for_platform(void);
int basebin_generate_internal(NSString *originUsrLibPath, NSString *basebinPath, NSString *targetBasebinPath, bool comingFromJBUpdate);
int basebin_generate(bool comingFromJBUpdate);

#endif