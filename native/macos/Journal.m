// SPDX-License-Identifier: GPL-3.0-only
#import "Journal.h"
#include <sqlite3.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>

static BOOL Scope(id value) {
    return [value isKindOfClass:NSString.class] && [value length] > 0
        && [value lengthOfBytesUsingEncoding:NSUTF8StringEncoding] <= 128
        && [value rangeOfCharacterFromSet:NSCharacterSet.controlCharacterSet].location == NSNotFound;
}

@interface NCJournal () {
    sqlite3 *_database;
    dispatch_queue_t _writer;
    dispatch_source_t _timer;
    NSObject *_gate;
    NSMutableArray *_pending;
    NSUInteger _pendingBytes;
    uint64_t _issued, _pendingDropped;
    BOOL _accepting, _closing;
    uint64_t _lastPrune;
    NSString *_epoch, *_instance, *_directory, *_failure;
    NSMutableDictionary *_meta;
    NSDictionary *_status;
    uid_t _owner;
}
- (instancetype)initWithInstance:(NSString *)instance path:(NSString *)directory owner:(uid_t)owner;
@end

@implementation NCJournal
- (instancetype)initWithInstance:(NSString *)instance {
    return [self initWithInstance:instance path:NCNativeDirectory(YES) owner:0];
}

#ifdef NC_JOURNAL_SELF_TEST
- (instancetype)initWithInstance:(NSString *)instance directory:(NSString *)directory {
    return [self initWithInstance:instance path:directory owner:getuid()];
}
- (void)flushForTest {
    dispatch_sync(_writer, ^{ for (NSUInteger page = 0; page < 4; page++) [self flush]; });
}
- (void)denyWritesForTest {
    dispatch_sync(_writer, ^{ NSCAssert([self sql:"PRAGMA query_only=ON"], @"Read-only failure fixture"); });
}
#endif

- (instancetype)initWithInstance:(NSString *)instance path:(NSString *)directory owner:(uid_t)owner {
    if ((self = [super init])) {
        _instance = [instance copy]; _directory = [directory copy]; _owner = owner;
        _writer = dispatch_queue_create("io.github.cosxin.network-control.journal", DISPATCH_QUEUE_SERIAL);
        _gate = [NSObject new]; _pending = [NSMutableArray array];
        _meta = [@{@"journalId":@"",@"generation":@0,@"recording":@NO,@"recordingEpoch":@"",@"lastSequence":@0,
            @"acknowledgedSequence":@0,@"droppedEvents":@0,@"providerRestarts":@0,@"retentionDays":@7,@"maxRecords":@10000} mutableCopy];
        dispatch_sync(_writer, ^{ [self open]; });
#ifndef NC_JOURNAL_SELF_TEST
        _timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, _writer);
        dispatch_source_set_timer(_timer, dispatch_time(DISPATCH_TIME_NOW, 250 * NSEC_PER_MSEC), 250 * NSEC_PER_MSEC, 25 * NSEC_PER_MSEC);
        __weak NCJournal *weak = self;
        dispatch_source_set_event_handler(_timer, ^{ [weak flush]; });
        dispatch_resume(_timer);
#endif
    }
    return self;
}

- (BOOL)filesSafe {
    struct stat metadata;
    if (!_directory || lstat(_directory.fileSystemRepresentation, &metadata) != 0 || !S_ISDIR(metadata.st_mode)
        || metadata.st_uid != _owner || (metadata.st_mode & 0077) != 0) return NO;
    for (NSString *name in @[@"history.sqlite",@"history.sqlite-journal",@"history.sqlite-wal",@"history.sqlite-shm"]) {
        NSString *path = [_directory stringByAppendingPathComponent:name];
        if (lstat(path.fileSystemRepresentation, &metadata) != 0) { if (errno == ENOENT) continue; return NO; }
        if (!S_ISREG(metadata.st_mode) || metadata.st_uid != _owner || metadata.st_nlink != 1
            || (metadata.st_mode & 0077) != 0 || metadata.st_size > ([name isEqual:@"history.sqlite"] ? 64 : 65) * 1024 * 1024
            || [name hasSuffix:@"-wal"] || [name hasSuffix:@"-shm"]) return NO;
    }
    return YES;
}

- (BOOL)sql:(const char *)sql {
    return _database && sqlite3_exec(_database, sql, NULL, NULL, NULL) == SQLITE_OK;
}

- (long long)scalar:(const char *)sql {
    sqlite3_stmt *statement = NULL;
    long long result = -1;
    if (sqlite3_prepare_v2(_database, sql, -1, &statement, NULL) == SQLITE_OK && sqlite3_step(statement) == SQLITE_ROW)
        result = sqlite3_column_int64(statement, 0);
    sqlite3_finalize(statement);
    return result;
}

- (void)publish {
    uint64_t first = [_meta[@"lastSequence"] unsignedLongLongValue] + 1;
    if (_database && !_failure) {
        long long minimum = [self scalar:"SELECT COALESCE(MIN(seq),0) FROM events"];
        if (minimum < 0) _failure = @"Native journal read failed; saved data preserved";
        else if (minimum > 0) first = (uint64_t)minimum;
    }
    NSMutableDictionary *status = [_meta mutableCopy];
    status[@"firstSequence"] = @(first);
    status[@"healthy"] = @(_failure == nil && _database != NULL);
    status[@"reason"] = _failure ?: @"Bounded durable TCP/UDP flow metadata; capture and final bytes can be incomplete";
    @synchronized (_gate) {
        _status = [status copy];
        _epoch = [_meta[@"recordingEpoch"] copy];
        _accepting = !_failure && !_closing && [_meta[@"recording"] boolValue];
    }
}

- (BOOL)saveMeta:(NSDictionary *)meta {
    NSData *encoded = NCEncode(meta);
    sqlite3_stmt *statement = NULL;
    BOOL saved = encoded && encoded.length <= 16384
        && sqlite3_prepare_v2(_database, "INSERT OR REPLACE INTO metadata(id,body) VALUES(1,?)", -1, &statement, NULL) == SQLITE_OK
        && sqlite3_bind_blob(statement, 1, encoded.bytes, (int)encoded.length, SQLITE_TRANSIENT) == SQLITE_OK
        && sqlite3_step(statement) == SQLITE_DONE;
    sqlite3_finalize(statement);
    return saved;
}

- (void)fail {
#ifdef NC_JOURNAL_SELF_TEST
    fprintf(stderr, "Journal fixture failure: %s (%d, errno %d)\n", _database ? sqlite3_errmsg(_database) : "open refused", _database ? sqlite3_extended_errcode(_database) : 0, errno);
#endif
    [self sql:"ROLLBACK"];
    _failure = @"Native journal storage failed; recording suspended and existing data preserved";
    @synchronized (_gate) { _accepting = NO; [_pending removeAllObjects]; _pendingBytes = 0; }
    [self publish];
}

- (void)open {
    if (!Scope(_instance) || ![self filesSafe]) { _failure = @"Native journal directory or files are not private and owner-protected"; [self publish]; return; }
    NSString *path = [_directory stringByAppendingPathComponent:@"history.sqlite"];
    BOOL exists = [NSFileManager.defaultManager fileExistsAtPath:path];
    if (!exists) {
        int file = open(path.fileSystemRepresentation, O_CREAT | O_EXCL | O_RDWR | O_NOFOLLOW, 0600);
        if (file < 0) { [self fail]; return; }
        close(file);
    }
    int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_PRIVATECACHE | SQLITE_OPEN_NOFOLLOW;
    if (sqlite3_open_v2(path.fileSystemRepresentation, &_database, flags, NULL) != SQLITE_OK) { [self fail]; return; }
    sqlite3_busy_timeout(_database, 1000);
    sqlite3_limit(_database, SQLITE_LIMIT_LENGTH, 32768);
    if (exists) {
        sqlite3_stmt *check = NULL;
        BOOL valid = [self scalar:"PRAGMA user_version"] == 1
            && sqlite3_prepare_v2(_database, "PRAGMA quick_check", -1, &check, NULL) == SQLITE_OK
            && sqlite3_step(check) == SQLITE_ROW && sqlite3_column_text(check, 0)
            && strcmp((const char *)sqlite3_column_text(check, 0), "ok") == 0;
        sqlite3_finalize(check);
        if (!valid) { [self fail]; return; }
        sqlite3_stmt *statement = NULL;
        NSDictionary *loaded = nil;
        if (sqlite3_prepare_v2(_database, "SELECT body FROM metadata WHERE id=1", -1, &statement, NULL) == SQLITE_OK
            && sqlite3_step(statement) == SQLITE_ROW) {
            loaded = NCDecode([NSData dataWithBytes:sqlite3_column_blob(statement, 0) length:(NSUInteger)sqlite3_column_bytes(statement, 0)]);
        }
        sqlite3_finalize(statement);
        BOOL validMeta = loaded.count == _meta.count && Scope(loaded[@"journalId"])
            && (Scope(loaded[@"recordingEpoch"]) || ([loaded[@"generation"] isEqual:@0] && [loaded[@"recording"] isEqual:@NO]));
        for (NSString *key in @[@"generation",@"lastSequence",@"acknowledgedSequence",@"droppedEvents",@"providerRestarts",@"retentionDays",@"maxRecords"])
            validMeta = validMeta && NCInteger(loaded[key]) && [loaded[key] unsignedLongLongValue] < LLONG_MAX;
        validMeta = validMeta && CFGetTypeID((__bridge CFTypeRef)(loaded[@"recording"] ?: NSNull.null)) == CFBooleanGetTypeID()
            && [loaded[@"acknowledgedSequence"] unsignedLongLongValue] <= [loaded[@"lastSequence"] unsignedLongLongValue]
            && [loaded[@"retentionDays"] unsignedLongLongValue] >= 1 && [loaded[@"retentionDays"] unsignedLongLongValue] <= 90
            && [loaded[@"maxRecords"] unsignedLongLongValue] >= 100 && [loaded[@"maxRecords"] unsignedLongLongValue] <= 20000;
        if (!validMeta) { [self fail]; return; }
        _meta = [loaded mutableCopy];
    } else {
        if (![self sql:"PRAGMA auto_vacuum=INCREMENTAL; CREATE TABLE metadata(id INTEGER PRIMARY KEY CHECK(id=1),body BLOB NOT NULL); CREATE TABLE events(seq INTEGER PRIMARY KEY,time_ms INTEGER NOT NULL,body BLOB NOT NULL); PRAGMA user_version=1;"]) { [self fail]; return; }
        _meta[@"journalId"] = NSUUID.UUID.UUIDString;
    }
    if (![self sql:"PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA secure_delete=ON; PRAGMA temp_store=MEMORY;"]) { [self fail]; return; }
    long long pageSize = [self scalar:"PRAGMA page_size"];
    if (pageSize < 512 || pageSize > 65536) { [self fail]; return; }
    NSString *cap = [NSString stringWithFormat:@"PRAGMA max_page_count=%lld", (64LL * 1024 * 1024) / pageSize];
    if (![self sql:cap.UTF8String] || ![self filesSafe]) { [self fail]; return; }
    _meta[@"providerRestarts"] = @([_meta[@"providerRestarts"] unsignedLongLongValue] + 1);
    if (![self sql:"BEGIN IMMEDIATE"] || ![self saveMeta:_meta] || ![self sql:"COMMIT"]) { [self fail]; return; }
    _issued = [_meta[@"lastSequence"] unsignedLongLongValue];
    [self publish];
}

- (NSDictionary *)status {
    @synchronized (_gate) { return [_status copy]; }
}

- (void)enqueue:(NSDictionary *)event {
    [self enqueue:event recordingToken:[self recordingToken]];
}

- (NSString *)recordingToken {
    @synchronized (_gate) { return _accepting ? _epoch : nil; }
}

- (void)enqueue:(NSDictionary *)event recordingToken:(NSString *)token {
    @synchronized (_gate) {
        if (!_accepting || !token || ![token isEqual:_epoch]) return;
        if (_issued >= LLONG_MAX - 1) { _accepting = NO; dispatch_async(_writer, ^{ [self fail]; }); return; }
        uint64_t sequence = ++_issued;
        NSDictionary *envelope = @{@"journalSequence":@(sequence),@"producerInstanceId":_instance,@"recordingEpoch":_epoch,
            @"providerRestarts":_status[@"providerRestarts"],@"event":[event copy]};
        NSData *encoded = NCEncode(envelope);
        if (!encoded || encoded.length > 16384 || _pending.count >= 1024 || _pendingBytes + encoded.length > 4 * 1024 * 1024) { _pendingDropped++; return; }
        [_pending addObject:@{@"body":encoded,@"envelope":envelope}]; _pendingBytes += encoded.length;
    }
}

- (BOOL)prune:(NSMutableDictionary *)meta {
    uint64_t now = (uint64_t)(NSDate.date.timeIntervalSince1970 * 1000);
    uint64_t duration = [meta[@"retentionDays"] unsignedLongLongValue] * 86400000;
    NSString *sql = [NSString stringWithFormat:@"DELETE FROM events WHERE seq<=%llu; DELETE FROM events WHERE time_ms<%llu; DELETE FROM events WHERE seq NOT IN (SELECT seq FROM events ORDER BY seq DESC LIMIT %u);",
        [meta[@"acknowledgedSequence"] unsignedLongLongValue],
        now > duration ? now - duration : 0,
        [meta[@"maxRecords"] unsignedIntValue]];
    long long before = [self scalar:"SELECT COUNT(*) FROM events"];
    if (before < 0 || ![self sql:sql.UTF8String]) return NO;
    sqlite3_stmt *sizes = NULL;
    if (sqlite3_prepare_v2(_database, "SELECT seq,LENGTH(body) FROM events ORDER BY seq DESC", -1, &sizes, NULL) != SQLITE_OK) return NO;
    uint64_t bytes = 0, floor = 0;
    int result;
    while ((result = sqlite3_step(sizes)) == SQLITE_ROW) {
        bytes += (uint64_t)sqlite3_column_int64(sizes, 1);
        if (bytes > 16 * 1024 * 1024) break;
        floor = (uint64_t)sqlite3_column_int64(sizes, 0);
    }
    BOOL bounded = result == SQLITE_DONE || result == SQLITE_ROW;
    sqlite3_finalize(sizes);
    if (!bounded) return NO;
    if (result == SQLITE_ROW) {
        NSString *trim = [NSString stringWithFormat:@"DELETE FROM events WHERE seq<%llu", floor];
        if (floor == 0 || ![self sql:trim.UTF8String]) return NO;
    }
    long long after = [self scalar:"SELECT COUNT(*) FROM events"];
    if (after < 0) return NO;
    meta[@"droppedEvents"] = @(MIN((uint64_t)LLONG_MAX - 1, [meta[@"droppedEvents"] unsignedLongLongValue] + (uint64_t)(before - after)));
    return YES;
}

- (void)flush {
    if (!_database || _failure) return;
    NSArray *batch;
    uint64_t lost;
    @synchronized (_gate) {
        NSUInteger count = MIN(_pending.count, 256);
        batch = [_pending subarrayWithRange:NSMakeRange(0, count)];
        for (NSDictionary *item in batch) _pendingBytes -= [item[@"body"] length];
        [_pending removeObjectsInRange:NSMakeRange(0, count)];
        lost = _pendingDropped; _pendingDropped = 0;
    }
    uint64_t now = (uint64_t)(NSDate.date.timeIntervalSince1970 * 1000);
    if (batch.count == 0 && lost == 0 && now - _lastPrune < 60000) return;
    NSMutableDictionary *next = [_meta mutableCopy];
    next[@"droppedEvents"] = @(MIN((uint64_t)LLONG_MAX - 1, [next[@"droppedEvents"] unsignedLongLongValue] + lost));
    if (![self filesSafe] || ![self sql:"BEGIN IMMEDIATE"]) { [self fail]; return; }
    for (NSDictionary *item in batch) {
        NSDictionary *envelope = item[@"envelope"];
        if (![next[@"recording"] boolValue] || ![envelope[@"recordingEpoch"] isEqual:next[@"recordingEpoch"]]) continue;
        sqlite3_stmt *statement = NULL;
        NSData *body = item[@"body"];
        BOOL saved = sqlite3_prepare_v2(_database, "INSERT INTO events(seq,time_ms,body) VALUES(?,?,?)", -1, &statement, NULL) == SQLITE_OK
            && sqlite3_bind_int64(statement, 1, [envelope[@"journalSequence"] longLongValue]) == SQLITE_OK
            && sqlite3_bind_int64(statement, 2, [envelope[@"event"][@"timeMs"] longLongValue]) == SQLITE_OK
            && sqlite3_bind_blob(statement, 3, body.bytes, (int)body.length, SQLITE_TRANSIENT) == SQLITE_OK && sqlite3_step(statement) == SQLITE_DONE;
        sqlite3_finalize(statement);
        if (!saved) { [self fail]; return; }
        next[@"lastSequence"] = envelope[@"journalSequence"];
    }
    if (![self prune:next] || ![self saveMeta:next] || ![self sql:"COMMIT"]) { [self fail]; return; }
    _meta = next; _lastPrune = now; [self publish];
}

- (NSDictionary *)process:(NSDictionary *)request {
    NSString *command = request[@"command"];
    NSString *error = nil;
    if (_failure || !_database) error = _failure ?: @"Native journal is unavailable";
    else if (![request[@"expectedInstanceId"] isEqual:_instance]) error = @"Native provider instance changed";
    else if ([command isEqual:@"journal-recording"]) {
        BOOL enabled = CFGetTypeID((__bridge CFTypeRef)(request[@"enabled"] ?: NSNull.null)) == CFBooleanGetTypeID()
            && [request[@"enabled"] boolValue];
        if (request.count != 8 || ![request[@"expectedJournalId"] isEqual:_meta[@"journalId"]]
            || !NCInteger(request[@"expectedGeneration"]) || ![request[@"expectedGeneration"] isEqual:_meta[@"generation"]]
            || [_meta[@"generation"] unsignedLongLongValue] >= LLONG_MAX - 1 || !Scope(request[@"recordingEpoch"])
            || CFGetTypeID((__bridge CFTypeRef)(request[@"enabled"] ?: NSNull.null)) != CFBooleanGetTypeID()
            || !NCInteger(request[@"retentionDays"]) || [request[@"retentionDays"] unsignedLongLongValue] < 1 || [request[@"retentionDays"] unsignedLongLongValue] > 90
            || !NCInteger(request[@"maxRecords"]) || [request[@"maxRecords"] unsignedLongLongValue] < 100 || [request[@"maxRecords"] unsignedLongLongValue] > 20000)
            error = @"Native recording scope, generation or limits changed";
        else {
            BOOL sameEpoch = [request[@"recordingEpoch"] isEqual:_meta[@"recordingEpoch"]];
            if (sameEpoch && enabled != [_meta[@"recording"] boolValue])
                return @{@"schemaVersion":@1,@"ok":@NO,@"error":@"A recording toggle requires a fresh epoch"};
            if (!sameEpoch) {
                @synchronized (_gate) { _accepting = NO; [_pending removeAllObjects]; _pendingBytes = 0; _pendingDropped = 0; }
            }
            NSMutableDictionary *next = [_meta mutableCopy];
            next[@"generation"] = @([next[@"generation"] unsignedLongLongValue] + 1); next[@"recording"] = @(enabled);
            next[@"recordingEpoch"] = request[@"recordingEpoch"]; next[@"retentionDays"] = request[@"retentionDays"]; next[@"maxRecords"] = request[@"maxRecords"];
            if (!sameEpoch) next[@"acknowledgedSequence"] = next[@"lastSequence"];
            if (![self filesSafe] || ![self sql:"BEGIN IMMEDIATE"] || (sameEpoch ? ![self prune:next] : ![self sql:"DELETE FROM events"])
                || ![self saveMeta:next] || ![self sql:"COMMIT"]) { [self fail]; error = _failure; }
            else { _meta = next; if (!sameEpoch) { @synchronized (_gate) { _issued = [next[@"lastSequence"] unsignedLongLongValue]; } } [self publish]; }
        }
    } else if (![request[@"journalId"] isEqual:_meta[@"journalId"]] || ![request[@"recordingEpoch"] isEqual:_meta[@"recordingEpoch"]]) error = @"Native journal or recording epoch changed";
    else if ([command isEqual:@"journal-ack"]) {
        if (request.count != 5 || !NCInteger(request[@"throughSequence"]) || [request[@"throughSequence"] unsignedLongLongValue] > [_meta[@"lastSequence"] unsignedLongLongValue]) error = @"Native acknowledgment exceeds durable events";
        else {
            NSMutableDictionary *next = [_meta mutableCopy];
            next[@"acknowledgedSequence"] = @(MAX([next[@"acknowledgedSequence"] unsignedLongLongValue], [request[@"throughSequence"] unsignedLongLongValue]));
            NSString *sql = [NSString stringWithFormat:@"BEGIN IMMEDIATE; DELETE FROM events WHERE seq<=%llu", [next[@"acknowledgedSequence"] unsignedLongLongValue]];
            if (![self filesSafe] || ![self sql:sql.UTF8String] || ![self saveMeta:next] || ![self sql:"COMMIT"]) { [self fail]; error = _failure; }
            else { _meta = next; [self publish]; }
        }
    } else if ([command isEqual:@"journal-events"]) {
        uint64_t after = NCInteger(request[@"afterSequence"]) ? [request[@"afterSequence"] unsignedLongLongValue] : 0;
        NSUInteger limit = NCInteger(request[@"limit"]) ? [request[@"limit"] unsignedIntegerValue] : 0;
        if (request.count != 6 || !NCInteger(request[@"afterSequence"]) || after > [_meta[@"lastSequence"] unsignedLongLongValue]
            || !NCInteger(request[@"limit"]) || limit < 1 || limit > 256) error = @"Invalid native journal page bounds";
        else {
            sqlite3_stmt *statement = NULL;
            NSMutableArray *events = [NSMutableArray array]; uint64_t next = after;
            BOOL valid = sqlite3_prepare_v2(_database, "SELECT body FROM events WHERE seq>? ORDER BY seq LIMIT ?", -1, &statement, NULL) == SQLITE_OK
                && sqlite3_bind_int64(statement, 1, (sqlite3_int64)after) == SQLITE_OK && sqlite3_bind_int64(statement, 2, (sqlite3_int64)limit) == SQLITE_OK;
            int result = valid ? sqlite3_step(statement) : SQLITE_ERROR;
            NSUInteger bytes = 1024;
            while (result == SQLITE_ROW) {
                NSUInteger length = (NSUInteger)sqlite3_column_bytes(statement, 0);
                if (bytes + length > 1024 * 1024 - 1024) break;
                NSDictionary *envelope = NCDecode([NSData dataWithBytes:sqlite3_column_blob(statement, 0) length:length]);
                if (!envelope || !NCInteger(envelope[@"journalSequence"]) || [envelope[@"journalSequence"] unsignedLongLongValue] <= next
                    || ![envelope[@"recordingEpoch"] isEqual:_meta[@"recordingEpoch"]] || !Scope(envelope[@"producerInstanceId"])) { valid = NO; break; }
                [events addObject:envelope]; next = [envelope[@"journalSequence"] unsignedLongLongValue]; bytes += length;
                result = sqlite3_step(statement);
            }
            valid = valid && (result == SQLITE_DONE || result == SQLITE_ROW);
            sqlite3_finalize(statement);
            if (!valid) { [self fail]; error = _failure; }
            else return @{@"schemaVersion":@1,@"ok":@YES,@"instanceId":_instance,@"journalId":_meta[@"journalId"],@"recordingEpoch":_meta[@"recordingEpoch"],
                @"firstSequence":_status[@"firstSequence"],@"lastSequence":_meta[@"lastSequence"],@"nextSequence":@(next),
                @"providerRestarts":_meta[@"providerRestarts"],@"droppedEvents":_meta[@"droppedEvents"],@"events":events};
        }
    } else error = @"Unsupported native journal command";
    return error ? @{@"schemaVersion":@1,@"ok":@NO,@"error":error} : @{@"schemaVersion":@1,@"ok":@YES,@"journal":[self status]};
}

- (void)request:(NSDictionary *)request reply:(void (^)(NSDictionary *))reply {
    dispatch_async(_writer, ^{ reply([self process:request]); });
}

- (void)close {
    if (_timer) dispatch_source_cancel(_timer);
    dispatch_sync(_writer, ^{
        @synchronized (self->_gate) { self->_accepting = NO; self->_closing = YES; }
        for (NSUInteger page = 0; page < 4; page++) [self flush];
        sqlite3_close(self->_database); self->_database = NULL;
        self->_failure = @"Native journal is stopped"; [self publish];
    });
}
@end
