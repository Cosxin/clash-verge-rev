// SPDX-License-Identifier: GPL-3.0-only
#import "Journal.h"
#include <stdio.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>

static NSDictionary *Call(NCJournal *journal, NSDictionary *request) {
    dispatch_semaphore_t done = dispatch_semaphore_create(0);
    __block NSDictionary *result;
    [journal request:request reply:^(NSDictionary *reply) { result = reply; dispatch_semaphore_signal(done); }];
    NSCAssert(dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC)) == 0, @"Journal test deadline");
    return result;
}

static NSDictionary *Configure(NCJournal *journal, NSString *instance, NSString *epoch, BOOL enabled) {
    NSDictionary *status = [journal status];
    return Call(journal, @{@"command":@"journal-recording",@"expectedInstanceId":instance,@"expectedJournalId":status[@"journalId"],
        @"expectedGeneration":status[@"generation"],@"enabled":@(enabled),@"recordingEpoch":epoch,@"retentionDays":@7,@"maxRecords":@100});
}

static NSDictionary *Page(NCJournal *journal, NSString *instance, uint64_t after) {
    NSDictionary *status = [journal status];
    return Call(journal, @{@"command":@"journal-events",@"expectedInstanceId":instance,@"journalId":status[@"journalId"],
        @"recordingEpoch":status[@"recordingEpoch"],@"afterSequence":@(after),@"limit":@256});
}

int main(void) {
    @autoreleasepool {
        char temporary[] = "/tmp/network-control-journal-XXXXXX";
        NSCAssert(mkdtemp(temporary) != NULL, @"Private test directory");
        char canonical[PATH_MAX];
        NSCAssert(realpath(temporary, canonical) != NULL, @"Canonical private directory");
        NSString *directory = [NSString stringWithUTF8String:canonical];
        NSString *database = [directory stringByAppendingPathComponent:@"history.sqlite"];
        NSDictionary *event = @{@"flowId":@"test-flow",@"sequence":@17,@"timeMs":@((uint64_t)(NSDate.date.timeIntervalSince1970 * 1000)),
            @"kind":@"open",@"identityConfidence":@"unknown",@"sourceIp":@"127.0.0.1",@"sourcePort":@1234,
            @"destinationIp":@"127.0.0.1",@"destinationPort":@443,@"network":@"tcp",@"counterSemantics":@"cumulative",@"verdict":@"observe"};
        NCJournal *first = [[NCJournal alloc] initWithInstance:@"provider-a" directory:directory];
        NSCAssert([[first status][@"healthy"] boolValue] && ![[first status][@"recording"] boolValue], @"No implicit consent: %@", [first status]);
        [first enqueue:event]; [first flushForTest];
        NSCAssert([[first status][@"lastSequence"] isEqual:@0], @"Off data not persisted");
        NSCAssert([Configure(first, @"provider-a", @"recording-a", YES)[@"ok"] boolValue], @"Durable enable");
        [first enqueue:event]; [first flushForTest];
        NSDictionary *page = Page(first, @"provider-a", 0);
        NSCAssert([page[@"ok"] boolValue] && [page[@"events"] count] == 1, @"GUI absent committed event");
        NSCAssert([page[@"events"][0][@"event"][@"sequence"] isEqual:@17] && [page[@"nextSequence"] isEqual:@1], @"Delivery and producer sequence distinct");
        NSString *identity = [first status][@"journalId"];
        [first close];
        NCJournal *second = [[NCJournal alloc] initWithInstance:@"provider-b" directory:directory];
        NSCAssert([[second status][@"journalId"] isEqual:identity] && [[second status][@"providerRestarts"] isEqual:@2], @"Restart identity preserved");
        page = Page(second, @"provider-b", 0);
        NSCAssert([page[@"events"][0][@"producerInstanceId"] isEqual:@"provider-a"], @"Original source survives restart");
        NSDictionary *ack = @{@"command":@"journal-ack",@"expectedInstanceId":@"provider-b",@"journalId":identity,@"recordingEpoch":@"recording-a",@"throughSequence":@2};
        NSCAssert(![Call(second, ack)[@"ok"] boolValue], @"Future acknowledgment rejected");
        NSMutableDictionary *accepted = [ack mutableCopy]; accepted[@"throughSequence"] = @1;
        NSCAssert([Call(second, accepted)[@"ok"] boolValue] && [Call(second, accepted)[@"ok"] boolValue], @"Acknowledgment is idempotent");
        NSCAssert([Page(second, @"provider-b", 1)[@"events"] count] == 0, @"Only acknowledged prefix removed");
        NSString *oldToken = [second recordingToken];
        [second enqueue:event];
        NSCAssert([Configure(second, @"provider-b", @"recording-off", NO)[@"ok"] boolValue], @"Off fences queued work");
        [second enqueue:event]; [second flushForTest];
        NSCAssert([[second status][@"lastSequence"] isEqual:@1], @"Disabled backlog not saved");
        NSCAssert([Configure(second, @"provider-b", @"recording-b", YES)[@"ok"] boolValue], @"Explicit new epoch");
        [second enqueue:event recordingToken:oldToken]; [second flushForTest];
        NSCAssert([[second status][@"lastSequence"] isEqual:@1], @"Old callback cannot cross recording epochs");
        [second enqueue:event];
        NSCAssert([Configure(second, @"provider-b", @"recording-b", YES)[@"ok"] boolValue], @"Retention-only configuration");
        [second flushForTest];
        NSCAssert([Page(second, @"provider-b", 1)[@"events"] count] == 1, @"Retention changes preserve queued frames");
        NSCAssert(![Configure(second, @"provider-b", @"recording-b", NO)[@"ok"] boolValue], @"Toggle cannot reuse an epoch");
        NSCAssert([Configure(second, @"provider-b", @"recording-c", YES)[@"ok"] boolValue], @"Fresh overflow fixture");
        for (NSUInteger i = 0; i < 1040; i++) [second enqueue:event];
        [second flushForTest]; [second enqueue:event]; [second flushForTest];
        page = Page(second, @"provider-b", 1026);
        NSCAssert([page[@"ok"] boolValue] && [page[@"events"] count] == 1 && [page[@"nextSequence"] isEqual:@1043], @"Bounded queue loss has sequence evidence");
        NSCAssert([[second status][@"droppedEvents"] unsignedLongLongValue] >= 16, @"Overflow visible");
        NSCAssert(![Page(second, @"provider-a", 0)[@"ok"] boolValue], @"Stale provider refused");
        struct stat permissions;
        NSCAssert(lstat(database.fileSystemRepresentation, &permissions) == 0 && (permissions.st_mode & 0077) == 0, @"Private database");
        [second denyWritesForTest];
        [second enqueue:event]; [second flushForTest];
        NSCAssert(![[second status][@"healthy"] boolValue] && [[second status][@"lastSequence"] isEqual:@1043], @"Failed write cannot advance durable head");
        [second close];
        NCJournal *recovered = [[NCJournal alloc] initWithInstance:@"provider-recovered" directory:directory];
        NSCAssert([[recovered status][@"healthy"] boolValue] && [[recovered status][@"lastSequence"] isEqual:@1043]
            && [Page(recovered, @"provider-recovered", 1042)[@"events"] count] == 1, @"Failed write preserves replayable committed events");
        [recovered close];
        NSData *corrupt = [@"preserved invalid database" dataUsingEncoding:NSUTF8StringEncoding];
        NSCAssert([corrupt writeToFile:database atomically:NO], @"Corruption fixture");
        NCJournal *broken = [[NCJournal alloc] initWithInstance:@"provider-c" directory:directory];
        NSCAssert(![[broken status][@"healthy"] boolValue] && [[NSData dataWithContentsOfFile:database] isEqual:corrupt], @"Corrupt original preserved");
        [broken close];
        NSCAssert([NSFileManager.defaultManager removeItemAtPath:database error:nil], @"Remove owned fixture");
        NSString *target = [directory stringByAppendingPathComponent:@"target"];
        NSCAssert([corrupt writeToFile:target atomically:NO] && symlink(target.fileSystemRepresentation, database.fileSystemRepresentation) == 0, @"Symlink fixture");
        NCJournal *link = [[NCJournal alloc] initWithInstance:@"provider-d" directory:directory];
        NSCAssert(![[link status][@"healthy"] boolValue] && [[NSData dataWithContentsOfFile:target] isEqual:corrupt], @"Symlink refused without touching target");
        [link close];
        [NSFileManager.defaultManager removeItemAtPath:directory error:nil];
        puts("{\"schemaVersion\":1,\"ok\":true,\"nativeProviderConstructed\":false,\"nativeOperationsPerformed\":false}");
    }
    return 0;
}
