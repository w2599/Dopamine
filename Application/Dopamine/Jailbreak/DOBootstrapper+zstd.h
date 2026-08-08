//
//  Bootstrapper.h
//  Dopamine
//
//  Created by Lars Fröder on 09.01.24.
//

#import <Foundation/Foundation.h>

#import "DOBootstrapper.h"

NS_ASSUME_NONNULL_BEGIN

@interface DOBootstrapper (zstd)

- (NSError *)decompressZstd:(NSString *)zstdPath toTar:(NSString *)tarPath;

@end

NS_ASSUME_NONNULL_END
