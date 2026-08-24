const std = @import("std");

const HttpClient = @This();

const Response = @import("response.zig").Response;

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

pub fn post(self: *HttpClient, comptime R: type, url: []const u8, body_data: []const u8, auth: []const u8) !if (R == void) std.http.Status else Response(R) {
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

    const body = try body_writer.toOwnedSlice();
    errdefer self.allocator.free(body);

    if (response.status != .ok) {
        return .{
            .status = response.status,
            .body = body,
            .parsed = null,
            .allocator = self.allocator,
        };
    }

    const parsed = std.json.parseFromSlice(R, self.allocator, body, .{ .allocate = .alloc_always, .ignore_unknown_fields = true }) catch {
        // Some providers (e.g. GitHub) return a 200 with an OAuth error document
        // that does not match `R`. Keep the body so the caller can inspect it.
        return .{
            .status = response.status,
            .body = body,
            .parsed = null,
            .allocator = self.allocator,
        };
    };

    self.allocator.free(body);

    return .{
        .status = response.status,
        .body = "",
        .parsed = parsed,
        .allocator = self.allocator,
    };
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

    var response = try client.post(ResponseBody, url, body, "Bearer testtoken");
    defer response.deinit();

    try std.testing.expect(std.mem.eql(u8, response.parsed.?.value.form.key, "value"));
}
