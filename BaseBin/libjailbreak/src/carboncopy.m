#import <Foundation/Foundation.h>
#import <sandbox.h>
#import <sys/param.h>
#import <sys/mount.h>
#import <copyfile.h>
#import <sys/types.h>
#import <sys/stat.h>

NSArray *writableFileAttributes(void)
{
	static NSArray *attributes = nil;
	static dispatch_once_t onceToken;
	dispatch_once (&onceToken, ^{
		attributes = @[NSFileBusy, NSFileCreationDate, NSFileExtensionHidden, NSFileGroupOwnerAccountID, NSFileGroupOwnerAccountName, NSFileHFSCreatorCode, NSFileHFSTypeCode, NSFileImmutable, NSFileModificationDate, NSFileOwnerAccountID, NSFileOwnerAccountName, NSFilePosixPermissions];
	});
	return attributes;
}

NSDictionary *writableAttributes(NSDictionary *attributes)
{
	NSArray *writableAttributes = writableFileAttributes();
	NSMutableDictionary *newDict = [NSMutableDictionary new];

	[attributes enumerateKeysAndObjectsUsingBlock:^(NSString *attributeKey, NSObject *attribute, BOOL *stop) {
		if([writableAttributes containsObject:attributeKey]) {
			newDict[attributeKey] = attribute;
		}
	}];

	return newDict.copy;
}

bool fileExistsOrSymlink(NSString *path, BOOL *isDirectory, BOOL *isSymlink)
{
	NSDictionary<NSString *,id> *attributes = [[NSFileManager defaultManager] attributesOfItemAtPath:path error:nil];
	if (isSymlink) {
		*isSymlink = [attributes[NSFileType] isEqualToString:NSFileTypeSymbolicLink];
	}
	if ([[NSFileManager defaultManager] fileExistsAtPath:path isDirectory:isDirectory]) return YES;
	return attributes ? YES : NO;
}

int carbonCopySingle(NSString *sourcePath, NSString *targetPath)
{
	BOOL isDirectory = NO, sourceIsSymlink = NO;
	BOOL exists = fileExistsOrSymlink(sourcePath, &isDirectory, &sourceIsSymlink);
	if (!exists) {
		return 1;
	}

	if (fileExistsOrSymlink(targetPath, nil, nil)) {
		[[NSFileManager defaultManager] removeItemAtPath:targetPath error:nil];
	}

	NSDictionary* attributes = writableAttributes([[NSFileManager defaultManager] attributesOfItemAtPath:sourcePath error:nil]);
	if (sourceIsSymlink) {
		NSString *destPath = [[NSFileManager defaultManager] destinationOfSymbolicLinkAtPath:sourcePath error:nil];
		if ([[NSFileManager defaultManager] createSymbolicLinkAtPath:targetPath withDestinationPath:destPath error:nil]) {
			// Ultra hacky
			int fd = open(targetPath.fileSystemRepresentation, O_RDWR | O_SYMLINK);
			if (fd >= 0) {
				NSNumber *perms = attributes[NSFilePosixPermissions];
				if (perms) {
					fchmod(fd, perms.intValue);
				}

				NSNumber *accountId = attributes[NSFileOwnerAccountID];
				NSNumber *groupId = attributes[NSFileGroupOwnerAccountID];
				if (accountId && groupId) {
					fchown(fd, accountId.intValue, groupId.intValue);
				}

				close(fd);
			}
			return 0;
		}
		return 1;
	}
	else if (isDirectory) {
		return [[NSFileManager defaultManager] createDirectoryAtPath:targetPath withIntermediateDirectories:NO attributes:attributes error:nil] != YES;
	}
	else {
		if ([[NSFileManager defaultManager] copyItemAtPath:sourcePath toPath:targetPath error:nil]) {
			[[NSFileManager defaultManager] setAttributes:attributes ofItemAtPath:targetPath error:nil];
			return 0;
		}
		return 1;
	}
}

int carbonCopy(NSString *sourcePath, NSString *targetPath)
{
	int retval = 0;
	BOOL isDirectory = NO;
	BOOL exists = fileExistsOrSymlink(sourcePath, &isDirectory, nil);
	if (exists) {
		if (isDirectory) {
			retval = carbonCopySingle(sourcePath, targetPath);
			if (retval == 0) {
				NSDirectoryEnumerator *enumerator = [[NSFileManager defaultManager] enumeratorAtPath:sourcePath];
				for (NSString *relativePath in enumerator) {
					@autoreleasepool {
						NSString *subSourcePath = [sourcePath stringByAppendingPathComponent:relativePath];
						NSString *subTargetPath = [targetPath stringByAppendingPathComponent:relativePath];
						retval = carbonCopySingle(subSourcePath, subTargetPath);
						if (retval != 0) break;
					}
				}
			}
			
		}
		else {
			retval = carbonCopySingle(sourcePath, targetPath);
		}
	}
	else {
		retval = 1;
	}
	return retval;
}
