// SPDX-License-Identifier: GPL-3.0-only
#import "Native.h"

@interface NCJournal : NSObject
- (instancetype)initWithInstance:(NSString *)instance;
- (NSDictionary *)status;
- (NSString *)recordingToken;
- (void)enqueue:(NSDictionary *)event;
- (void)enqueue:(NSDictionary *)event recordingToken:(NSString *)token;
- (void)request:(NSDictionary *)request reply:(void (^)(NSDictionary *))reply;
- (void)close;
#ifdef NC_JOURNAL_SELF_TEST
- (instancetype)initWithInstance:(NSString *)instance directory:(NSString *)directory;
- (void)flushForTest;
- (void)denyWritesForTest;
#endif
@end
