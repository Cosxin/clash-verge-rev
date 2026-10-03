// SPDX-License-Identifier: GPL-3.0-only
#import "Native.h"
#import <Security/Security.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

static NSString *const Directory = @"/Library/Application Support/NetworkControl/native-macos";

NSString *NCRequirement(NSString *identifier) {
    if (strlen(NC_TEAM_ID) != 10) return nil;
    return [NSString stringWithFormat:@"anchor apple generic and identifier \"%@\" and certificate leaf[subject.OU] = \"%s\"", identifier, NC_TEAM_ID];
}

BOOL NCSignedOwner(NSString *identifier) {
    NSString *text = NCRequirement(identifier);
    if (!text || NC_OWNER_UID < 0) return NO;
    SecCodeRef code = NULL;
    SecRequirementRef requirement = NULL;
    CFDictionaryRef info = NULL;
    BOOL valid = SecCodeCopySelf(kSecCSDefaultFlags, &code) == errSecSuccess
        && SecRequirementCreateWithString((__bridge CFStringRef)text, kSecCSDefaultFlags, &requirement) == errSecSuccess
        && SecCodeCheckValidity(code, kSecCSDefaultFlags, requirement) == errSecSuccess
        && SecCodeCopySigningInformation(code, kSecCSSigningInformation, &info) == errSecSuccess;
    if (valid) valid = [((__bridge NSDictionary *)info)[(__bridge NSString *)kSecCodeInfoFlags] unsignedIntValue] & kSecCodeSignatureRuntime;
    if (info) CFRelease(info);
    if (requirement) CFRelease(requirement);
    if (code) CFRelease(code);
    return valid;
}

NSDictionary *NCDecode(NSData *data) {
    if (data.length == 0 || data.length > 1024 * 1024) return nil;
    id value = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    return [value isKindOfClass:NSDictionary.class] ? value : nil;
}

NSData *NCEncode(NSDictionary *value) {
    return [NSJSONSerialization dataWithJSONObject:value options:0 error:nil];
}

BOOL NCInteger(id value) {
    return [value isKindOfClass:NSNumber.class] && CFGetTypeID((__bridge CFTypeRef)value) != CFBooleanGetTypeID()
        && !CFNumberIsFloatType((__bridge CFNumberRef)value) && [value compare:@0] != NSOrderedAscending;
}

NSString *NCValidatePolicy(NSDictionary *policy) {
    if (![policy isKindOfClass:NSDictionary.class] || policy.count != 3 || !NCInteger(policy[@"schemaVersion"])
        || [policy[@"schemaVersion"] unsignedIntValue] != 1 || !NCInteger(policy[@"generation"])
        || ![policy[@"processPaths"] isKindOfClass:NSArray.class] || [policy[@"processPaths"] count] > 512) {
        return @"Native policy requires schema 1, generation and up to 512 paths";
    }
    NSMutableSet *unique = [NSMutableSet set];
    for (id path in policy[@"processPaths"]) {
        if (![path isKindOfClass:NSString.class] || [path lengthOfBytesUsingEncoding:NSUTF8StringEncoding] > 2048
            || ![path hasPrefix:@"/"] || [path isEqual:@"/"] || ![[path stringByStandardizingPath] isEqual:path]
            || [path rangeOfCharacterFromSet:NSCharacterSet.controlCharacterSet].location != NSNotFound
            || [unique containsObject:path]) return @"Native bans require unique canonical absolute executable paths";
        [unique addObject:path];
    }
    return nil;
}

NSDictionary *NCUnavailable(NSString *reason) {
    return @{@"schemaVersion":@1, @"ok":@YES, @"platform":@"macos", @"installed":@NO, @"active":@NO,
        @"authenticated":@NO, @"policyInitialized":@NO, @"monitoring":@NO, @"generation":@0,
        @"processPaths":@[], @"instanceId":@"", @"existingFlowBehavior":@"unavailable", @"reason":reason};
}

static BOOL NCDirectory(BOOL create) {
    for (NSString *path in @[@"/Library", @"/Library/Application Support", @"/Library/Application Support/NetworkControl", Directory]) {
        struct stat metadata;
        if (lstat(path.fileSystemRepresentation, &metadata) != 0) {
            if (!create || ![path hasPrefix:@"/Library/Application Support/NetworkControl"]
                || mkdir(path.fileSystemRepresentation, 0700) != 0
                || lstat(path.fileSystemRepresentation, &metadata) != 0) return NO;
        }
        if (!S_ISDIR(metadata.st_mode) || metadata.st_uid != 0 || (metadata.st_mode & 0022) != 0) return NO;
    }
    return YES;
}

NSDictionary *NCLoadPolicy(NSString **failure) {
    NSString *path = [Directory stringByAppendingPathComponent:@"policy.json"];
    if (![NSFileManager.defaultManager fileExistsAtPath:path]) return nil;
    struct stat metadata;
    if (!NCDirectory(NO) || lstat(path.fileSystemRepresentation, &metadata) != 0 || !S_ISREG(metadata.st_mode)
        || metadata.st_uid != 0 || (metadata.st_mode & 0077) != 0 || metadata.st_size > 1024 * 1024) {
        *failure = @"Native policy ownership or size is invalid; original preserved";
        return nil;
    }
    NSDictionary *policy = NCDecode([NSData dataWithContentsOfFile:path]);
    *failure = NCValidatePolicy(policy);
    return *failure ? nil : policy;
}

BOOL NCSavePolicy(NSDictionary *policy, NSString **failure) {
    if (!NCDirectory(YES)) { *failure = @"Native policy directory is not root-owned and private"; return NO; }
    NSString *temporary = [Directory stringByAppendingPathComponent:[@".policy-" stringByAppendingString:NSUUID.UUID.UUIDString]];
    NSData *encoded = NCEncode(policy);
    int file = open(temporary.fileSystemRepresentation, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW, 0600);
    BOOL saved = file >= 0;
    if (saved) {
        const uint8_t *bytes = encoded.bytes;
        NSUInteger remaining = encoded.length;
        while (remaining > 0) {
            ssize_t written = write(file, bytes, remaining);
            if (written <= 0) { saved = NO; break; }
            remaining -= (NSUInteger)written;
            bytes += written;
        }
        if (saved) saved = fsync(file) == 0;
        close(file);
    }
    if (saved) saved = rename(temporary.fileSystemRepresentation, [Directory stringByAppendingPathComponent:@"policy.json"].fileSystemRepresentation) == 0;
    if (saved) {
        int directory = open(Directory.fileSystemRepresentation, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
        saved = directory >= 0 && fsync(directory) == 0;
        if (directory >= 0) close(directory);
    }
    unlink(temporary.fileSystemRepresentation);
    if (!saved) *failure = @"Native policy persistence failed; acknowledgement withheld";
    return saved;
}
