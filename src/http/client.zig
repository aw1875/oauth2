const std = @import("std");

const HttpClient = @This();

allocator: std.mem.Allocator,
_client: std.http.Client,

pub fn init(allocator: std.mem.Allocator) !HttpClient {
    return .{
        .allocator = allocator,
        ._client = std.http.Client{ .allocator = allocator },
    };
}

pub fn deinit(self: *HttpClient) void {
    self._client.deinit();
}

pub fn post(self: *HttpClient, comptime R: type, url: []const u8, body_data: []const u8, auth: []const u8) !if (R == void) std.http.Status else std.json.Parsed(R) {
    var response_storage = std.ArrayList(u8).init(self.allocator);
    defer response_storage.deinit();

    const response = try self._client.fetch(.{
        .location = .{ .url = url },
        .method = .POST,
        .headers = .{
            .authorization = .{ .override = auth },
            .content_type = .{ .override = "application/x-www-form-urlencoded" },
        },
        .payload = body_data,
        .extra_headers = &[_]std.http.Header{
            .{ .name = "User-Agent", .value = "oauth2.zig" },
            .{ .name = "Accept", .value = "application/json" },
        },
        .response_storage = .{ .dynamic = &response_storage },
    });

    if (R == void) return response.status;
    if (response.status != .ok) {
        std.log.scoped(.oauth2).err("HTTP request failed with reason: {s}", .{response.status.phrase() orelse "Unknown error"});
        return error.HttpError;
    }

    return try std.json.parseFromSlice(R, self.allocator, response_storage.items, .{ .allocate = .alloc_always, .ignore_unknown_fields = true });
}
