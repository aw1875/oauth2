const std = @import("std");

const HttpClient = @This();

io: std.Io,
allocator: std.mem.Allocator,
_client: std.http.Client,

pub fn init(io: std.Io, allocator: std.mem.Allocator) !HttpClient {
    return .{
        .io = io,
        .allocator = allocator,
        ._client = std.http.Client{ .allocator = allocator, .io = io },
    };
}

pub fn deinit(self: *HttpClient) void {
    self._client.deinit();
}

pub fn post(self: *HttpClient, comptime R: type, url: []const u8, body_data: []const u8, auth: []const u8) !if (R == void) std.http.Status else std.json.Parsed(R) {
    var body_writer: std.Io.Writer.Allocating = .init(self.allocator);
    defer body_writer.deinit();

    const response = try self._client.fetch(.{
        .location = .{ .url = url },
        .method = .POST,
        .headers = .{
            .authorization = if (auth.len == 0) .omit else .{ .override = auth },
            .content_type = .{ .override = "application/x-www-form-urlencoded" },
        },
        .payload = body_data,
        .extra_headers = &[_]std.http.Header{
            .{ .name = "User-Agent", .value = "oauth2.zig" },
            .{ .name = "Accept", .value = "application/json" },
        },
        .response_writer = &body_writer.writer,
    });

    if (R == void) return response.status;
    if (response.status != .ok) {
        std.log.scoped(.oauth2).err("HTTP request failed with reason: {s}", .{response.status.phrase() orelse "Unknown error"});
        return error.HttpError;
    }

    const body = try body_writer.toOwnedSlice();
    defer self.allocator.free(body);

    return try std.json.parseFromSlice(R, self.allocator, body, .{ .allocate = .alloc_always, .ignore_unknown_fields = true });
}

test "HttpClient POST request" {
    const allocator = std.testing.allocator;

    var client = try HttpClient.init(std.testing.io, allocator);
    defer client.deinit();

    const url = "https://postman-echo.com/post";
    const body = "key=value";

    const ResponseBody = struct {
        form: struct {
            key: []const u8,
        },
    };

    const response = try client.post(ResponseBody, url, body, "Bearer testtoken");
    defer response.deinit();

    try std.testing.expect(std.mem.eql(u8, response.value.form.key, "value"));
}
