const std = @import("std");

const crypto = @import("crypto.zig");
const HttpClient = @import("http.zig");
const Response = @import("response.zig").Response;
const utils = @import("utils.zig");

pub const OAuth2ProviderArgs = struct {
    client_id: []const u8,
    client_secret: []const u8,
    redirect_uri: []const u8,
};

pub const Param = struct {
    key: []const u8,
    value: []const u8,
};

client: *HttpClient,
client_id: []const u8,
client_secret: []const u8,
redirect_uri: []const u8,

const OAuth2Provider = @This();

pub fn init(io: std.Io, allocator: std.mem.Allocator, args: OAuth2ProviderArgs) !OAuth2Provider {
    const http_client = try allocator.create(HttpClient);
    http_client.* = try HttpClient.init(io, allocator);

    return OAuth2Provider{
        .client = http_client,
        .client_id = args.client_id,
        .client_secret = args.client_secret,
        .redirect_uri = args.redirect_uri,
    };
}

pub fn deinit(self: *OAuth2Provider) void {
    self.client.deinit();
    self.client.allocator.destroy(self.client);
}

/// How the PKCE code challenge was derived. `plain` exists because RFC 7636
/// defines it; `S256` is the one to use, and the only one a server is required
/// to support.
pub const CodeChallengeMethod = enum {
    S256,
    plain,

    fn value(self: CodeChallengeMethod) []const u8 {
        return @tagName(self);
    }
};

const Pkce = struct {
    method: CodeChallengeMethod,
    verifier: []const u8,
};

pub fn createAuthorizationUrl(
    self: *const OAuth2Provider,
    allocator: std.mem.Allocator,
    authorization_endpoint: []const u8,
    state: []const u8,
    scopes: []const []const u8,
    extra_params: []const Param,
) ![]const u8 {
    return self.buildAuthorizationUrl(allocator, authorization_endpoint, state, scopes, null, extra_params);
}

pub fn createAuthorizationUrlWithPKCE(
    self: *const OAuth2Provider,
    allocator: std.mem.Allocator,
    authorization_endpoint: []const u8,
    state: []const u8,
    code_challenge_method: CodeChallengeMethod,
    code_verifier: []const u8,
    scopes: []const []const u8,
    extra_params: []const Param,
) ![]const u8 {
    return self.buildAuthorizationUrl(allocator, authorization_endpoint, state, scopes, .{
        .method = code_challenge_method,
        .verifier = code_verifier,
    }, extra_params);
}

/// The one place an authorization URL is assembled. Everything intermediate
/// goes in a scratch arena and only the finished URL is handed back, so a
/// caller with a plain allocator is not quietly leaking an encoded scope list
/// and a code challenge on every call.
fn buildAuthorizationUrl(
    self: *const OAuth2Provider,
    allocator: std.mem.Allocator,
    authorization_endpoint: []const u8,
    state: []const u8,
    scopes: []const []const u8,
    pkce: ?Pkce,
    extra_params: []const Param,
) ![]const u8 {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var out: std.ArrayList(u8) = .empty;

    try out.appendSlice(a, authorization_endpoint);
    try out.appendSlice(a, "?response_type=code");
    try appendParam(a, &out, "client_id", self.client_id);
    try appendParam(a, &out, "redirect_uri", self.redirect_uri);
    try appendParam(a, &out, "state", state);

    if (pkce) |challenge| {
        try appendParam(a, &out, "code_challenge_method", challenge.method.value());
        try appendParam(a, &out, "code_challenge", try crypto.sha256Base64UrlSafe(a, challenge.verifier));
    }

    // An empty `scope=` is not the same as no scope at all, and servers that
    // care reject the first one.
    if (scopes.len > 0) {
        try appendParam(a, &out, "scope", try std.mem.join(a, " ", scopes));
    }

    for (extra_params) |param| try appendParam(a, &out, param.key, param.value);

    return allocator.dupe(u8, out.items);
}

fn appendParam(a: std.mem.Allocator, out: *std.ArrayList(u8), name: []const u8, value: []const u8) !void {
    try out.append(a, '&');
    try out.appendSlice(a, try utils.urlEncode(a, name, .url));
    try out.append(a, '=');
    try out.appendSlice(a, try utils.urlEncode(a, value, .url));
}

pub fn validateAuthorizationCode(
    self: *const OAuth2Provider,
    comptime T: type,
    allocator: std.mem.Allocator,
    token_endpoint: []const u8,
    code: []const u8,
    code_verifier: ?[]const u8,
    extra_params: []const Param,
) !Response(T) {
    var form_data = std.StringHashMap([]const u8).init(allocator);
    defer form_data.deinit();

    try form_data.put("code", code);
    try form_data.put("client_id", self.client_id);
    try form_data.put("redirect_uri", self.redirect_uri);
    try form_data.put("grant_type", "authorization_code");
    if (code_verifier) |verifier| try form_data.put("code_verifier", verifier);
    for (extra_params) |param| try form_data.put(param.key, param.value);

    const body_data = try utils.formEncode(allocator, form_data);
    defer allocator.free(body_data);

    const auth = try self.createBasicAuthHeader(allocator);
    defer allocator.free(auth);

    return self.client.post(T, token_endpoint, body_data, auth);
}

pub fn refreshAccessToken(
    self: *const OAuth2Provider,
    comptime T: type,
    allocator: std.mem.Allocator,
    token_endpoint: []const u8,
    refresh_token: []const u8,
    scopes: ?[]const []const u8,
    extra_params: []const Param,
) !Response(T) {
    var form_data = std.StringHashMap([]const u8).init(allocator);
    defer form_data.deinit();

    try form_data.put("refresh_token", refresh_token);
    try form_data.put("client_id", self.client_id);
    try form_data.put("grant_type", "refresh_token");
    // Freed at the end of the function, not the end of the `if`: the form
    // holds this slice until `formEncode` has read it.
    var joined_scopes: ?[]const u8 = null;
    defer if (joined_scopes) |joined| allocator.free(joined);
    if (scopes) |s| {
        if (s.len > 0) {
            joined_scopes = try std.mem.join(allocator, " ", s);
            try form_data.put("scope", joined_scopes.?);
        }
    }
    for (extra_params) |param| try form_data.put(param.key, param.value);

    const body_data = try utils.formEncode(allocator, form_data);
    defer allocator.free(body_data);

    const auth = try self.createBasicAuthHeader(allocator);
    defer allocator.free(auth);

    return self.client.post(T, token_endpoint, body_data, auth);
}

pub fn revokeAccessToken(
    self: *const OAuth2Provider,
    allocator: std.mem.Allocator,
    token_revocation_endpoint: []const u8,
    access_token: []const u8,
) !void {
    var form_data = std.StringHashMap([]const u8).init(allocator);
    defer form_data.deinit();

    try form_data.put("token", access_token);
    try form_data.put("client_id", self.client_id);

    const body_data = try utils.formEncode(allocator, form_data);
    defer allocator.free(body_data);

    const auth = try self.createBasicAuthHeader(allocator);
    defer allocator.free(auth);

    const response = try self.client.post(void, token_revocation_endpoint, body_data, auth);

    if (response != .ok) return error.HttpError;
}

/// The `Authorization` header for a token request, or an empty string when
/// there is none to send.
///
/// RFC 6749 section 2.3.1: a client authenticates one way, never two. With a
/// secret that is HTTP Basic, which the spec says to prefer; without one the
/// client is public and identifies itself with `client_id` in the body alone.
/// Sending the secret in both places is what trips servers that check.
fn createBasicAuthHeader(self: *const OAuth2Provider, allocator: std.mem.Allocator) ![]const u8 {
    if (self.client_secret.len == 0) return allocator.dupe(u8, "");
    const auth_string = try std.fmt.allocPrint(allocator, "{s}:{s}", .{ self.client_id, self.client_secret });
    defer allocator.free(auth_string);

    const auth_encoded = try allocator.alloc(u8, std.base64.standard.Encoder.calcSize(auth_string.len));
    defer allocator.free(auth_encoded);
    _ = std.base64.standard.Encoder.encode(auth_encoded, auth_string);

    return std.fmt.allocPrint(allocator, "Basic {s}", .{auth_encoded});
}

const testing = std.testing;

fn testProvider(secret: []const u8) !OAuth2Provider {
    return init(testing.io, testing.allocator, .{
        .client_id = "client-id",
        .client_secret = secret,
        .redirect_uri = "http://127.0.0.1:9999/cb",
    });
}

test "an authorization url carries the fixed parameters, encoded" {
    var provider = try testProvider("");
    defer provider.deinit();

    const url = try provider.createAuthorizationUrl(
        testing.allocator,
        "https://auth.example/authorize",
        "state-abc",
        &.{ "read", "write" },
        &.{},
    );
    defer testing.allocator.free(url);

    try testing.expect(std.mem.startsWith(u8, url, "https://auth.example/authorize?response_type=code"));
    try testing.expect(std.mem.indexOf(u8, url, "&client_id=client-id") != null);
    try testing.expect(std.mem.indexOf(u8, url, "&state=state-abc") != null);
    try testing.expect(std.mem.indexOf(u8, url, "&scope=read%20write") != null);
    try testing.expect(std.mem.indexOf(u8, url, "&redirect_uri=http%3A%2F%2F127.0.0.1%3A9999%2Fcb") != null);
}

test "an empty scope list produces no scope parameter at all" {
    var provider = try testProvider("");
    defer provider.deinit();

    const url = try provider.createAuthorizationUrl(
        testing.allocator,
        "https://auth.example/authorize",
        "state-abc",
        &.{},
        &.{},
    );
    defer testing.allocator.free(url);

    try testing.expect(std.mem.indexOf(u8, url, "scope=") == null);
}

test "extra parameters are appended and encoded" {
    var provider = try testProvider("");
    defer provider.deinit();

    const url = try provider.createAuthorizationUrl(
        testing.allocator,
        "https://auth.example/authorize",
        "state-abc",
        &.{},
        &.{.{ .key = "resource", .value = "https://mcp.example/mcp" }},
    );
    defer testing.allocator.free(url);

    try testing.expect(std.mem.indexOf(u8, url, "&resource=https%3A%2F%2Fmcp.example%2Fmcp") != null);
}

test "PKCE adds the method and the derived challenge" {
    var provider = try testProvider("");
    defer provider.deinit();

    const url = try provider.createAuthorizationUrlWithPKCE(
        testing.allocator,
        "https://auth.example/authorize",
        "state-abc",
        .S256,
        "hello",
        &.{},
        &.{},
    );
    defer testing.allocator.free(url);

    try testing.expect(std.mem.indexOf(u8, url, "&code_challenge_method=S256") != null);
    // The known SHA-256 of "hello", base64url without padding.
    try testing.expect(std.mem.indexOf(u8, url, "&code_challenge=LPJNul-wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ") != null);
}

test "a public client sends no authorization header" {
    var provider = try testProvider("");
    defer provider.deinit();

    const header = try provider.createBasicAuthHeader(testing.allocator);
    defer testing.allocator.free(header);

    try testing.expectEqualStrings("", header);
}

test "a confidential client authenticates with Basic" {
    var provider = try testProvider("shh");
    defer provider.deinit();

    const header = try provider.createBasicAuthHeader(testing.allocator);
    defer testing.allocator.free(header);

    // base64("client-id:shh")
    try testing.expectEqualStrings("Basic Y2xpZW50LWlkOnNoaA==", header);
}
