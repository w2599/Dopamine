#import <Foundation/Foundation.h>

@interface DORuntimeConfiguration : NSObject
+ (NSError *)prepare;
+ (NSError *)restoreCustomMounts;
@end
