const std = @import("std");

pub fn urlEncode(allocator: std.mem.Allocator, input: []const u8, mode: enum { url, form }) ![]const u8 {
    var out = std.ArrayList(u8).init(allocator);
    defer out.deinit();

    for (input) |c| {
        switch (c) {
            'a'...'z', 'A'...'Z', '0'...'9', '-', '_', '.', '~' => try out.writer().writeByte(c),
            ' ' => switch (mode) {
                .url => try out.writer().print("%{X:0>2}", .{c}),
                .form => try out.writer().writeByte('+'),
            },
            else => try out.writer().print("%{X:0>2}", .{c}),
        }
    }

    return out.toOwnedSlice();
}

test "urlEncode in form mode" {
    const allocator = std.testing.allocator;

    const result = try urlEncode(allocator, "hello world!", .form);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("hello+world%21", result);
}

test "urlEncode in url mode" {
    const allocator = std.testing.allocator;

    const result = try urlEncode(allocator, "hello world!", .url);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("hello%20world%21", result);
}

test "urlEncode special characters" {
    const allocator = std.testing.allocator;

    const result = try urlEncode(allocator, "!@#$%^&*()", .form);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("%21%40%23%24%25%5E%26%2A%28%29", result);
}

test "urlEncode unreserved characters" {
    const allocator = std.testing.allocator;

    const input = "AZaz09-_.~";
    const result = try urlEncode(allocator, input, .url);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("AZaz09-_.~", result);
}

pub fn formEncode(allocator: std.mem.Allocator, data: std.StringHashMap([]const u8)) ![]const u8 {
    var out = std.ArrayList(u8).init(allocator);
    defer out.deinit();

    var iter = data.iterator();
    var first = true;
    var writer = out.writer();

    while (iter.next()) |entry| {
        const key = entry.key_ptr.*;
        const value = entry.value_ptr.*;

        const encoded_key = try urlEncode(allocator, key, .form);
        const encoded_value = try urlEncode(allocator, value, .form);
        defer {
            allocator.free(encoded_key);
            allocator.free(encoded_value);
        }

        if (!first) {
            try writer.writeByte('&');
        } else {
            first = false;
        }

        try writer.print("{s}={s}", .{ encoded_key, encoded_value });
    }

    return out.toOwnedSlice();
}

test "formEncode encodes single key-value pair" {
    const allocator = std.testing.allocator;

    var map = std.StringHashMap([]const u8).init(allocator);
    defer map.deinit();

    try map.put("key", "value with spaces");
    const encoded = try formEncode(allocator, map);
    defer allocator.free(encoded);

    try std.testing.expect(std.mem.eql(u8, encoded, "key=value+with+spaces"));
}

test "formEncode encodes multiple pairs joined by &" {
    const allocator = std.testing.allocator;

    var map = std.StringHashMap([]const u8).init(allocator);
    defer map.deinit();

    try map.put("a", "1");
    try map.put("b", "2");
    try map.put("c", "3");

    const encoded = try formEncode(allocator, map);
    defer allocator.free(encoded);

    // The exact order is unknown; check all parts present and separated by &
    try std.testing.expect(std.mem.containsAtLeast(u8, encoded, 1, "a=1"));
    try std.testing.expect(std.mem.containsAtLeast(u8, encoded, 1, "b=2"));
    try std.testing.expect(std.mem.containsAtLeast(u8, encoded, 1, "c=3"));
    try std.testing.expect(std.mem.indexOf(u8, encoded, "&") != null);
}

test "formEncode percent-encodes reserved characters" {
    const allocator = std.testing.allocator;

    var map = std.StringHashMap([]const u8).init(allocator);
    defer map.deinit();

    try map.put("key=with=special", "value&with&special");
    const encoded = try formEncode(allocator, map);
    defer allocator.free(encoded);

    try std.testing.expect(std.mem.containsAtLeast(u8, encoded, 1, "key%3Dwith%3Dspecial="));
    try std.testing.expect(std.mem.containsAtLeast(u8, encoded, 1, "value%26with%26special"));
}

test "formEncode returns empty string on empty map" {
    const allocator = std.testing.allocator;

    var map = std.StringHashMap([]const u8).init(allocator);
    defer map.deinit();

    const encoded = try formEncode(allocator, map);
    defer allocator.free(encoded);

    try std.testing.expect(encoded.len == 0);
}
