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
    var server_header_buffer: [1024 * 1024 * 4]u8 = undefined;
    var req = try self._client.open(.POST, try std.Uri.parse(url), .{ .server_header_buffer = &server_header_buffer });
    defer req.deinit();

    req.headers.content_type = .{ .override = "application/x-www-form-urlencoded" };
    req.transfer_encoding = .{ .content_length = body_data.len };
    req.headers.accept_encoding = .{ .override = "application/json" };
    req.extra_headers = &[_]std.http.Header{.{ .name = "Authorization", .value = auth }};

    try req.send();
    try req.writeAll(body_data);
    try req.finish();
    try req.wait();

    if (R == void) return req.response.status;
    if (req.response.status != .ok) {
        std.log.scoped(.oauth2).err("HTTP request failed with reason: {s}", .{req.response.reason});
        return error.HttpError;
    }

    const response_data = try req.reader().readAllAlloc(self.allocator, 1024 * 1024 * 4);
    defer self.allocator.free(response_data);

    return try std.json.parseFromSlice(R, self.allocator, response_data, .{ .allocate = .alloc_always, .ignore_unknown_fields = true });
}
