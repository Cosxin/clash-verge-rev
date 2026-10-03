// SPDX-License-Identifier: GPL-3.0-only
// Audit-token identity and loopback filter rules adapted from LuLu (see NOTICE.md).
#import "Native.h"
#import <NetworkExtension/NetworkExtension.h>
#import <Security/Security.h>
#include <bsm/libbsm.h>
#include <netinet/in.h>
#include <stdio.h>

// Called while policyLock is held; a generation reused by a restarted
// provider must not authorize a request addressed to its predecessor.
static NSString *NCValidateBanRequest(NSDictionary *request, NSString *instance, uint64_t current) {
    id expectedInstance = request[@"expectedInstanceId"];
    if (![expectedInstance isKindOfClass:NSString.class] || [expectedInstance length] == 0
        || [expectedInstance lengthOfBytesUsingEncoding:NSUTF8StringEncoding] > 128
        || ![expectedInstance isEqual:instance]) return @"Native provider instance changed; refresh before applying";
    NSString *error = NCValidatePolicy(request[@"policy"]);
    if (error) return error;
    if (!NCInteger(request[@"expectedGeneration"])) return @"Invalid expected native ban generation";
    uint64_t expected = [request[@"expectedGeneration"] unsignedLongLongValue];
    if (expected != current || expected == UINT64_MAX
        || [request[@"policy"][@"generation"] unsignedLongLongValue] != expected + 1)
        return @"Native ban generation changed; refresh before applying";
    return nil;
}

static NSDictionary *NCIdentity(NEFilterFlow *flow) {
    NSData *token = flow.sourceAppAuditToken;
    if (token.length != sizeof(audit_token_t)) return @{};
    SecCodeRef code = NULL;
    CFURLRef location = NULL;
    CFDictionaryRef info = NULL;
    NSString *path = nil;
    if (SecCodeCopyGuestWithAttributes(NULL, (__bridge CFDictionaryRef)@{(__bridge NSString *)kSecGuestAttributeAudit:token},
        kSecCSDefaultFlags, &code) == errSecSuccess && SecCodeCopyPath(code, kSecCSDefaultFlags, &location) == errSecSuccess) {
        path = [(__bridge NSURL *)location path];
        BOOL directory = NO;
        if (![NSFileManager.defaultManager fileExistsAtPath:path isDirectory:&directory]) path = nil;
        else if (directory) {
            path = nil;
            if (SecCodeCopySigningInformation(code, kSecCSSigningInformation, &info) == errSecSuccess) {
                NSURL *executable = ((__bridge NSDictionary *)info)[(__bridge NSString *)kSecCodeInfoMainExecutable];
                if ([executable isKindOfClass:NSURL.class] && [NSFileManager.defaultManager fileExistsAtPath:executable.path isDirectory:&directory] && !directory) path = executable.path;
            }
        }
        path = path.stringByResolvingSymlinksInPath;
    }
    if (info) CFRelease(info);
    if (location) CFRelease(location);
    if (code) CFRelease(code);
    if (!path || NCValidatePolicy(@{@"schemaVersion":@1,@"generation":@0,@"processPaths":@[path]})) return @{};
    audit_token_t audit;
    [token getBytes:&audit length:sizeof(audit)];
    return @{@"processPath":path,@"pid":@(audit_token_to_pid(audit)),@"uid":@(audit_token_to_euid(audit)),@"identityConfidence":@"exact"};
}

@interface NCFilterDataProvider : NEFilterDataProvider <NSXPCListenerDelegate, NCControl>
@property (atomic, copy) NSDictionary *policy;
@property (atomic) BOOL active;
@property (atomic) BOOL authenticated;
@property (atomic, copy) NSString *failure;
@property (nonatomic, strong) NSString *instance;
@property (nonatomic, strong) NSXPCListener *listener;
@property (nonatomic, strong) NSObject *eventsLock;
@property (nonatomic, strong) NSObject *policyLock;
@property (nonatomic, strong) NSMutableArray *events;
@property (nonatomic, strong) NSMutableDictionary *identities;
@property (nonatomic) uint64_t sequence;
@property (nonatomic) uint64_t dropped;
@end

@implementation NCFilterDataProvider
- (instancetype)init {
    if ((self = [super init])) {
        _instance = NSUUID.UUID.UUIDString;
        _eventsLock = [NSObject new];
        _policyLock = [NSObject new];
        _events = [NSMutableArray array];
        _identities = [NSMutableDictionary dictionary];
        NSString *failure = nil;
        _policy = NCLoadPolicy(&failure);
        _failure = failure;
    }
    return self;
}

- (void)startFilterWithCompletionHandler:(void (^)(NSError *))completionHandler {
    self.authenticated = NCSignedOwner(NC_FILTER_ID);
    if (!self.authenticated) {
        completionHandler([NSError errorWithDomain:@"NetworkControl" code:1 userInfo:@{NSLocalizedDescriptionKey:@"A configured Developer ID publisher and owner UID are required"}]);
        return;
    }
    NSMutableArray *rules = [NSMutableArray array];
    for (NSNumber *direction in @[@(NETrafficDirectionOutbound),@(NETrafficDirectionInbound)]) {
        for (NSArray *loopback in @[@[@"127.0.0.0",@8],@[@"::1",@128]]) {
            NENetworkRule *network = [[NENetworkRule alloc] initWithRemoteNetwork:[NWHostEndpoint endpointWithHostname:loopback[0] port:@"0"]
                remotePrefix:[loopback[1] unsignedIntegerValue] localNetwork:nil localPrefix:0
                protocol:NENetworkRuleProtocolAny direction:[direction integerValue]];
            [rules addObject:[[NEFilterRule alloc] initWithNetworkRule:network action:NEFilterActionFilterData]];
        }
        NENetworkRule *network = [[NENetworkRule alloc] initWithRemoteNetwork:nil remotePrefix:0 localNetwork:nil localPrefix:0
            protocol:NENetworkRuleProtocolAny direction:[direction integerValue]];
        [rules addObject:[[NEFilterRule alloc] initWithNetworkRule:network action:NEFilterActionFilterData]];
    }
    [self applySettings:[[NEFilterSettings alloc] initWithRules:rules defaultAction:NEFilterActionDrop] completionHandler:^(NSError *error) {
        self.active = error == nil;
        if (!error) {
            self.listener = [[NSXPCListener alloc] initWithMachServiceName:[NSString stringWithFormat:@"%s.%@", NC_TEAM_ID, NC_FILTER_ID]];
            [self.listener setConnectionCodeSigningRequirement:NCRequirement(NC_CONTROLLER_ID)];
            self.listener.delegate = self;
            [self.listener resume];
        }
        completionHandler(error);
    }];
}

- (void)stopFilterWithReason:(NEProviderStopReason)reason completionHandler:(void (^)(void))completionHandler {
    self.active = NO;
    [self.listener invalidate];
    self.listener = nil;
    completionHandler();
}

- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)connection {
    if (!self.authenticated || (connection.effectiveUserIdentifier != (uid_t)NC_OWNER_UID && connection.effectiveUserIdentifier != 0)) return NO;
    connection.exportedInterface = [NSXPCInterface interfaceWithProtocol:@protocol(NCControl)];
    connection.exportedObject = self;
    [connection resume];
    return YES;
}

- (NSDictionary *)status {
    NSDictionary *policy = self.policy;
    uint64_t sequence, dropped;
    @synchronized (self.eventsLock) { sequence = self.sequence; dropped = self.dropped; }
    return @{@"schemaVersion":@1,@"ok":@YES,@"platform":@"macos",@"installed":@YES,@"active":@(self.active),
        @"authenticated":@(self.authenticated),@"policyInitialized":@(policy != nil),@"monitoring":@(self.active),
        @"eventSequence":@(sequence),@"droppedEvents":@(dropped),
        @"generation":policy[@"generation"] ?: @0,@"processPaths":policy[@"processPaths"] ?: @[],@"instanceId":self.instance,
        @"existingFlowBehavior":@"new_flows_only",@"coverage":@"tcp_udp_socket_flows",@"unknownIdentityAction":@"block",
        @"reason":self.failure ?: (policy ? @"TCP/UDP socket flows; existing-flow teardown is not guaranteed. History is a bounded volatile ring." : @"Policy uninitialized: flows are blocked until an explicit ban policy is committed")};
}

- (void)request:(NSData *)data reply:(void (^)(NSData *))reply {
    NSDictionary *request = NCDecode(data);
    NSString *command = request[@"command"];
    NSString *error = nil;
    if (![command isKindOfClass:NSString.class]) error = @"Invalid native command";
    else if ([command isEqual:@"status"] && request.count == 1) { reply(NCEncode([self status])); return; }
    else if ([command isEqual:@"apply-bans"] && request.count == 4) {
        @synchronized (self.policyLock) {
            NSDictionary *policy = request[@"policy"];
            uint64_t current = [self.policy[@"generation"] unsignedLongLongValue];
            error = NCValidateBanRequest(request, self.instance, current);
            if (!error && self.failure) error = self.failure;
            if (!error && !self.active) error = @"Native filter is not active";
            if (!error) {
                for (NSString *path in policy[@"processPaths"]) {
                    BOOL directory = NO;
                    if (![NSFileManager.defaultManager fileExistsAtPath:path isDirectory:&directory] || directory
                        || ![NSFileManager.defaultManager isExecutableFileAtPath:path] || ![path.stringByResolvingSymlinksInPath isEqual:path]) {
                        error = @"Native bans require an existing canonical executable file"; break;
                    }
                }
            }
            if (!error) {
                if (NCSavePolicy(policy, &error)) self.policy = [policy copy];
                else {
                    // A rename may succeed before directory fsync fails. Do
                    // not advertise the old policy while disk state is uncertain.
                    self.policy = nil;
                    self.failure = error ?: @"Native persistence is uncertain; restart and verify before applying";
                }
            }
            if (!error) { reply(NCEncode([self status])); return; }
        }
    } else if ([command isEqual:@"events"] && request.count == 3 && NCInteger(request[@"afterSequence"]) && NCInteger(request[@"limit"])) {
        uint64_t after = [request[@"afterSequence"] unsignedLongLongValue];
        NSUInteger limit = [request[@"limit"] unsignedIntegerValue];
        if (limit < 1 || limit > 256) error = @"Event limit must be 1-256";
        else {
            @synchronized (self.eventsLock) {
                NSMutableArray *page = [NSMutableArray array];
                uint64_t next = after;
                for (NSDictionary *event in self.events) {
                    uint64_t sequence = [event[@"sequence"] unsignedLongLongValue];
                    if (sequence > after && page.count < limit) { [page addObject:event]; next = sequence; }
                }
                reply(NCEncode(@{@"schemaVersion":@1,@"ok":@YES,@"instanceId":self.instance,@"events":page,
                    @"nextSequence":@(next),@"droppedEvents":@(self.dropped),@"lastSequence":@(self.sequence)}));
                return;
            }
        }
    } else error = @"Unsupported or malformed native request";
    reply(NCEncode(@{@"schemaVersion":@1,@"ok":@NO,@"error":error ?: @"Native policy was not committed"}));
}

- (void)append:(NEFilterSocketFlow *)flow identity:(NSDictionary *)identity kind:(NSString *)kind upload:(NSUInteger)upload download:(NSUInteger)download verdict:(NSString *)verdict generation:(NSNumber *)generation {
    NWHostEndpoint *local = [flow.localEndpoint isKindOfClass:NWHostEndpoint.class] ? (NWHostEndpoint *)flow.localEndpoint : nil;
    NWHostEndpoint *remote = [flow.remoteEndpoint isKindOfClass:NWHostEndpoint.class] ? (NWHostEndpoint *)flow.remoteEndpoint : nil;
    NSMutableDictionary *event = [identity mutableCopy];
    [event addEntriesFromDictionary:@{@"flowId":flow.identifier.UUIDString,@"kind":kind,@"timeMs":@((uint64_t)(NSDate.date.timeIntervalSince1970 * 1000)),
        @"identityConfidence":identity[@"identityConfidence"] ?: @"unknown",@"sourceIp":local.hostname ?: @"",@"sourcePort":@([local.port intValue]),
        @"destinationIp":remote.hostname ?: @"",@"destinationPort":@([remote.port intValue]),@"network":flow.socketProtocol == IPPROTO_TCP ? @"tcp" : @"udp",
        @"upload":@(upload),@"download":@(download),@"counterSemantics":@"cumulative",@"verdict":verdict,@"policyGeneration":generation ?: NSNull.null}];
    @synchronized (self.eventsLock) {
        event[@"sequence"] = @(++self.sequence);
        [self.events addObject:event];
        if (self.events.count > 5000) { [self.events removeObjectAtIndex:0]; self.dropped++; }
    }
}

- (NEFilterNewFlowVerdict *)handleNewFlow:(NEFilterFlow *)flow {
    if (![flow isKindOfClass:NEFilterSocketFlow.class]) return [NEFilterNewFlowVerdict dropVerdict];
    NEFilterSocketFlow *socket = (NEFilterSocketFlow *)flow;
    if (socket.socketProtocol != IPPROTO_TCP && socket.socketProtocol != IPPROTO_UDP) return [NEFilterNewFlowVerdict dropVerdict];
    NSDictionary *identity = NCIdentity(flow);
    NSDictionary *policy = self.policy;
    BOOL blocked = !policy || !identity[@"processPath"] || [policy[@"processPaths"] containsObject:identity[@"processPath"]];
    NSDictionary *evidence = @{@"identity":identity,@"verdict":blocked ? @"block" : @"allow",@"generation":policy[@"generation"] ?: NSNull.null};
    @synchronized (self.eventsLock) {
        if (self.identities.count >= 10000) { self.dropped++; }
        else self.identities[flow.identifier.UUIDString] = evidence;
    }
    [self append:socket identity:identity kind:@"open" upload:0 download:0 verdict:evidence[@"verdict"] generation:evidence[@"generation"]];
    NEFilterNewFlowVerdict *verdict = blocked ? [NEFilterNewFlowVerdict dropVerdict] : [NEFilterNewFlowVerdict allowVerdict];
    verdict.shouldReport = YES;
    verdict.statisticsReportFrequency = NEFilterReportFrequencyMedium;
    return verdict;
}

- (void)handleReport:(NEFilterReport *)report {
    if (![report.flow isKindOfClass:NEFilterSocketFlow.class] || (report.event != NEFilterReportEventStatistics && report.event != NEFilterReportEventFlowClosed)) return;
    NSDictionary *evidence;
    @synchronized (self.eventsLock) { evidence = self.identities[report.flow.identifier.UUIDString]; }
    NSString *kind = report.event == NEFilterReportEventFlowClosed ? @"close" : @"update";
    [self append:(NEFilterSocketFlow *)report.flow identity:evidence[@"identity"] ?: @{} kind:kind upload:report.bytesOutboundCount
        download:report.bytesInboundCount verdict:evidence[@"verdict"] ?: @"unknown" generation:evidence[@"generation"]];
    if (report.event == NEFilterReportEventFlowClosed) {
        @synchronized (self.eventsLock) { [self.identities removeObjectForKey:report.flow.identifier.UUIDString]; }
    }
}
@end

#ifdef NC_PROVIDER_SELF_TEST
// Pure validation only: no provider construction, XPC, policy I/O or filter
// activation. Compile this entry point separately for the request-CAS tests.
int main(int argc, char **argv) {
    @autoreleasepool {
        NSDictionary *request = @{@"command":@"apply-bans",@"expectedInstanceId":@"current-provider",
            @"expectedGeneration":@7,@"policy":@{@"schemaVersion":@1,@"generation":@8,@"processPaths":@[]}};
        BOOL valid = NCValidateBanRequest(request, @"current-provider", 7) == nil;
        valid = valid && NCValidateBanRequest(request, @"replacement-provider", 7) != nil;
        for (id instance in @[@"",@42,NSNull.null,[@"x" stringByPaddingToLength:129 withString:@"x" startingAtIndex:0]]) {
            NSMutableDictionary *invalid = [request mutableCopy];
            invalid[@"expectedInstanceId"] = instance;
            valid = valid && NCValidateBanRequest(invalid, @"current-provider", 7) != nil;
        }
        NSMutableDictionary *missing = [request mutableCopy];
        [missing removeObjectForKey:@"expectedInstanceId"];
        valid = valid && NCValidateBanRequest(missing, @"current-provider", 7) != nil;
        valid = valid && NCValidateBanRequest(request, @"current-provider", 8) != nil;
        for (id generation in @[@YES,@{},NSNull.null]) {
            NSMutableDictionary *invalid = [request mutableCopy];
            invalid[@"expectedGeneration"] = generation;
            valid = valid && NCValidateBanRequest(invalid, @"current-provider", 7) != nil;
        }
        NSMutableDictionary *wrongNext = [request mutableCopy];
        wrongNext[@"policy"] = @{@"schemaVersion":@1,@"generation":@7,@"processPaths":@[]};
        valid = valid && NCValidateBanRequest(wrongNext, @"current-provider", 7) != nil;
        NSData *result = NCEncode(@{@"schemaVersion":@1,@"ok":@(valid),@"nativeOperationsPerformed":@NO});
        fwrite(result.bytes, 1, result.length, stdout);
        fputc('\n', stdout);
        return valid ? 0 : 1;
    }
}
#else
int main(int argc, char **argv) {
    @autoreleasepool {
        [NEProvider startSystemExtensionMode];
        [NSRunLoop.currentRunLoop run];
    }
    return 0;
}
#endif
