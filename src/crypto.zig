const std = @import("std");
const crypto = std.crypto;

pub fn generateStateOrCodeVerifier(allocator: std.mem.Allocator) ![]const u8 {
    var rng: [32]u8 = undefined;
    crypto.random.bytes(&rng);

    const result = try allocator.alloc(u8, std.base64.url_safe_no_pad.Encoder.calcSize(rng.len));
    _ = std.base64.url_safe_no_pad.Encoder.encode(result, &rng);

    return result;
}

test "generateStateOrCodeVerifier returns 43-character base64url string" {
    const allocator = std.testing.allocator;
    const result = try generateStateOrCodeVerifier(allocator);
    defer allocator.free(result);

    // 32 random bytes => 43 Base64 (url-safe, no padding) characters
    try std.testing.expect(result.len == 43);
}

test "generateStateOrCodeVerifier returns URL-safe characters only" {
    const allocator = std.testing.allocator;
    const result = try generateStateOrCodeVerifier(allocator);
    defer allocator.free(result);

    for (result) |c| {
        try std.testing.expect((c >= 'A' and c <= 'Z') or
            (c >= 'a' and c <= 'z') or
            (c >= '0' and c <= '9') or
            (c == '-') or (c == '_'));
    }
}

test "generateStateOrCodeVerifier produces different results" {
    const allocator = std.testing.allocator;

    const a = try generateStateOrCodeVerifier(allocator);
    defer allocator.free(a);

    const b = try generateStateOrCodeVerifier(allocator);
    defer allocator.free(b);

    try std.testing.expect(!std.mem.eql(u8, a, b));
}

pub fn sha256Base64UrlSafe(allocator: std.mem.Allocator, input: []const u8) ![]const u8 {
    var hash: [32]u8 = undefined;
    crypto.hash.sha2.Sha256.hash(input, &hash, .{});

    const result = try allocator.alloc(u8, std.base64.url_safe_no_pad.Encoder.calcSize(hash.len));
    _ = std.base64.url_safe_no_pad.Encoder.encode(result, &hash);

    return result;
}

test "sha256Base64UrlSafe returns correct hash for known input" {
    const allocator = std.testing.allocator;
    const result = try sha256Base64UrlSafe(allocator, "hello");
    defer allocator.free(result);

    try std.testing.expectEqualStrings(
        "LPJNul-wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ",
        result,
    );
}

test "sha256Base64UrlSafe returns expected length (43 characters)" {
    const allocator = std.testing.allocator;
    const result = try sha256Base64UrlSafe(allocator, "some input");
    defer allocator.free(result);

    try std.testing.expect(result.len == 43);
}

test "sha256Base64UrlSafe uses URL-safe Base64 alphabet" {
    const allocator = std.testing.allocator;
    const result = try sha256Base64UrlSafe(allocator, "zig-lang");
    defer allocator.free(result);

    for (result) |c| {
        try std.testing.expect((c >= 'A' and c <= 'Z') or
            (c >= 'a' and c <= 'z') or
            (c >= '0' and c <= '9') or
            (c == '-') or (c == '_'));
    }
}
