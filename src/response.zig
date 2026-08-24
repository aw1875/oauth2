//! What a token request came back with.
//!
//! Its own file so that the public API can hand one of these back without
//! also handing out the HTTP client that produced it. Callers care about the
//! status, the parsed tokens, and the error document; how the request was
//! made is nobody's business but this package's.

const std = @import("std");

pub fn Response(comptime R: type) type {
    return struct {
        status: std.http.Status,
        /// Raw response body. Owned by this struct; freed by `deinit`.
        /// On a successful parse this is empty (the parsed value owns its own copies).
        body: []const u8,
        /// Parsed response body. `null` when the status is not `.ok` or the body
        /// could not be parsed as `R` (e.g. an OAuth error document).
        parsed: ?std.json.Parsed(R),

        allocator: std.mem.Allocator,

        pub fn deinit(self: *@This()) void {
            if (self.parsed) |*p| p.deinit();
            self.allocator.free(self.body);
        }

        /// The RFC 6749 error code the server sent, if it sent one.
        ///
        /// This is the whole reason an unparsed body is kept: a token endpoint
        /// reports `invalid_grant` and friends as a JSON document, sometimes
        /// with a 400 and sometimes - GitHub does this - with a 200. Either
        /// way the caller wants to know which, not just that something failed.
        ///
        /// The returned slices point into `body` and die with this struct.
        pub fn oauthError(self: @This()) ?struct { code: []const u8, description: ?[]const u8 } {
            if (self.body.len == 0) return null;

            var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, self.body, .{}) catch return null;
            defer parsed.deinit();

            const fields = switch (parsed.value) {
                .object => |object| object,
                else => return null,
            };

            const code = fields.get("error") orelse return null;
            if (code != .string) return null;

            // Located inside `body` rather than copied out of the parse arena,
            // which is about to be freed.
            const description = blk: {
                const value = fields.get("error_description") orelse break :blk null;
                if (value != .string) break :blk null;
                break :blk locate(self.body, value.string);
            };

            return .{ .code = locate(self.body, code.string) orelse return null, .description = description };
        }

        /// Find `needle`'s text back in `haystack`, so the returned slice
        /// outlives the parse that produced it.
        fn locate(haystack: []const u8, needle: []const u8) ?[]const u8 {
            const at = std.mem.indexOf(u8, haystack, needle) orelse return null;
            return haystack[at .. at + needle.len];
        }
    };
}

const testing = std.testing;

fn testResponse(body: []const u8) !Response(struct { access_token: []const u8 }) {
    return .{
        .status = .bad_request,
        .body = try testing.allocator.dupe(u8, body),
        .parsed = null,
        .allocator = testing.allocator,
    };
}

test "oauthError reads the code and the description" {
    var response = try testResponse(
        \\{"error":"invalid_grant","error_description":"Code expired"}
    );
    defer response.deinit();

    const err = response.oauthError().?;
    try testing.expectEqualStrings("invalid_grant", err.code);
    try testing.expectEqualStrings("Code expired", err.description.?);
}

test "oauthError returns the code alone when there is no description" {
    var response = try testResponse(
        \\{"error":"invalid_client"}
    );
    defer response.deinit();

    const err = response.oauthError().?;
    try testing.expectEqualStrings("invalid_client", err.code);
    try testing.expect(err.description == null);
}

test "oauthError is null for a body that carries no error" {
    var response = try testResponse(
        \\{"access_token":"abc"}
    );
    defer response.deinit();

    try testing.expect(response.oauthError() == null);
}

test "oauthError tolerates a body that is not an error document" {
    for ([_][]const u8{ "", "not json", "[1,2,3]", "{\"error\":500}" }) |body| {
        var response = try testResponse(body);
        defer response.deinit();
        try testing.expect(response.oauthError() == null);
    }
}

test "the returned slices survive the parse that produced them" {
    var response = try testResponse(
        \\{"error":"invalid_scope","error_description":"nope"}
    );
    defer response.deinit();

    const err = response.oauthError().?;

    // Pointing into `body`, not into the freed parse arena: the bytes are
    // still there and still say the same thing.
    try testing.expect(@intFromPtr(err.code.ptr) >= @intFromPtr(response.body.ptr));
    try testing.expect(@intFromPtr(err.code.ptr) < @intFromPtr(response.body.ptr) + response.body.len);
    try testing.expectEqualStrings("invalid_scope", err.code);
}
