// SPDX-License-Identifier: GPL-3.0-only
#import <Foundation/Foundation.h>

#ifndef NC_TEAM_ID
#define NC_TEAM_ID ""
#endif
#ifndef NC_OWNER_UID
#define NC_OWNER_UID -1
#endif
#define NC_FILTER_ID @"io.github.cosxin.network-control.filter"
#define NC_CONTROLLER_ID @"io.github.cosxin.network-control.native"

@protocol NCControl
- (void)request:(NSData *)data reply:(void (^)(NSData *))reply;
@end

NSString *NCRequirement(NSString *identifier);
BOOL NCSignedOwner(NSString *identifier);
NSDictionary *NCDecode(NSData *data);
NSData *NCEncode(NSDictionary *value);
NSString *NCValidatePolicy(NSDictionary *policy);
NSDictionary *NCUnavailable(NSString *reason);
BOOL NCInteger(id value);
BOOL NCSavePolicy(NSDictionary *policy, NSString **failure);
NSDictionary *NCLoadPolicy(NSString **failure);
