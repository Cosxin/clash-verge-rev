// SPDX-License-Identifier: GPL-3.0-only
#import "Native.h"
#include <stdio.h>
#include <unistd.h>

static void NCPrint(NSDictionary *value) {
    NSData *data = NCEncode(value);
    fwrite(data.bytes, 1, data.length, stdout);
    fputc('\n', stdout);
}

int main(int argc, char **argv) {
    @autoreleasepool {
        NSString *command = argc == 2 ? [NSString stringWithUTF8String:argv[1]] : @"";
        if ([command isEqual:@"self-test"]) {
            BOOL valid = NCValidatePolicy(@{@"schemaVersion":@1,@"generation":@1,@"processPaths":@[@"/usr/bin/curl"]}) == nil;
            valid = valid && NCValidatePolicy(@{@"schemaVersion":@1,@"generation":@1,@"processPaths":@[@"/usr/bin/../curl"]}) != nil;
            valid = valid && NCValidatePolicy(@{@"schemaVersion":@1,@"generation":@YES,@"processPaths":@[]}) != nil;
            valid = valid && NCValidatePolicy(@{@"schemaVersion":@1,@"generation":@1,@"processPaths":@[@"/usr/bin/curl",@"/usr/bin/curl"]}) != nil;
            NCPrint(@{@"schemaVersion":@1,@"ok":@(valid),@"nativeOperationsPerformed":@NO});
            return valid ? 0 : 1;
        }
        if (![@[@"status",@"apply-bans",@"events"] containsObject:command]) { NCPrint(@{@"schemaVersion":@1,@"ok":@NO,@"error":@"Expected status, apply-bans or events"}); return 1; }
        if (!NCSignedOwner(NC_CONTROLLER_ID) || (getuid() != (uid_t)NC_OWNER_UID && getuid() != 0)) {
            NCPrint(NCUnavailable(@"Native control requires the configured Developer ID signature, hardened runtime and owner UID; no provider connection was attempted"));
            return [command isEqual:@"status"] ? 0 : 1;
        }
        NSMutableDictionary *request = [NSMutableDictionary dictionary];
        if (![command isEqual:@"status"]) {
            NSMutableData *data = [NSMutableData data];
            uint8_t buffer[4096];
            ssize_t count;
            while ((count = read(STDIN_FILENO, buffer, sizeof(buffer))) > 0 && data.length <= 1024 * 1024) [data appendBytes:buffer length:(NSUInteger)count];
            NSDictionary *parsed = NCDecode(data);
            if (!parsed || count < 0) { NCPrint(@{@"schemaVersion":@1,@"ok":@NO,@"error":@"Invalid bounded JSON request"}); return 1; }
            [request addEntriesFromDictionary:parsed];
        }
        request[@"command"] = command;
        NSXPCConnection *connection = [[NSXPCConnection alloc] initWithMachServiceName:[NSString stringWithFormat:@"%s.%@", NC_TEAM_ID, NC_FILTER_ID] options:NSXPCConnectionPrivileged];
        [connection setCodeSigningRequirement:NCRequirement(NC_FILTER_ID)];
        connection.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(NCControl)];
        [connection resume];
        dispatch_semaphore_t done = dispatch_semaphore_create(0);
        __block NSData *response = nil;
        __block NSString *failure = nil;
        id<NCControl> proxy = [connection remoteObjectProxyWithErrorHandler:^(NSError *error) { failure = error.localizedDescription; dispatch_semaphore_signal(done); }];
        [proxy request:NCEncode(request) reply:^(NSData *data) { response = data; dispatch_semaphore_signal(done); }];
        BOOL timedOut = dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 4 * NSEC_PER_SEC)) != 0;
        [connection invalidate];
        NSDictionary *value = NCDecode(response);
        if (timedOut || failure || !value) { NCPrint(NCUnavailable(failure ?: @"Native provider did not acknowledge its state before the deadline")); return [command isEqual:@"status"] ? 0 : 1; }
        NCPrint(value);
        return [value[@"ok"] boolValue] ? 0 : 1;
    }
}
