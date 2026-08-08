//
//  grabkernel.h
//  libgrabkernel2
//
//  Created by Alfie on 14/02/2024.
//

#ifndef grabkernel_h
#define grabkernel_h

#include <Foundation/Foundation.h>

// Grab the kernelcache for the current device and save it to outPath
bool grab_kernelcache(NSString *outPath);
bool grab_kernelcache_for(NSString *osStr, NSString *build, NSString *modelIdentifier, NSString *boardConfig, NSString *outPath);

// Grab the kernelcache, SPTM and TXM for the current device and save them to outDir
bool grab_images(NSString *outDir);
bool grab_images_for(NSString *osStr, NSString *build, NSString *modelIdentifier, NSString *boardConfig, NSString *outDir);

// Uses details of the current device, but allows you to override the build number
bool grab_kernelcache_for_build_number(NSString *build, NSString *outPath);

// libgrabkernel compatibility shim
// Note that research kernel grabbing is not currently supported
int grabkernel(char *downloadPath, int isResearchKernel);

#endif /* grabkernel_h */