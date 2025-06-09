const std = @import("std");

const cryto = @import("../crypto.zig");
const HttpClient = @import("../http/client.zig");
const utils = @import("../utils.zig");

pub const OAuth2ProviderArgs = struct {
    client_id: []const u8,
    client_secret: []const u8,
    redirect_uri: []const u8,
};

client: *HttpClient,
client_id: []const u8,
client_secret: []const u8,
redirect_uri: []const u8,

const OAuth2Provider = @This();

pub fn init(allocator: std.mem.Allocator, args: OAuth2ProviderArgs) !OAuth2Provider {
    const http_client = try allocator.create(HttpClient);
    http_client.* = try HttpClient.init(allocator);

    return OAuth2Provider{
        .client = http_client,
        .client_id = args.client_id,
        .client_secret = args.client_secret,
        .redirect_uri = args.redirect_uri,
    };
}

pub fn deinit(self: *OAuth2Provider) void {
    self.client.deinit();
}

pub fn createAuthorizationUrl(
    self: *const OAuth2Provider,
    allocator: std.mem.Allocator,
    authorization_endpoint: []const u8,
    state: []const u8,
    scopes: []const []const u8,
) ![]const u8 {
    return try std.fmt.allocPrint(
        allocator,
        "{s}?response_type=code&client_id={s}&redirect_uri={s}&state={s}&scope={s}",
        .{
            authorization_endpoint,
            try utils.urlEncode(allocator, self.client_id, .url),
            try utils.urlEncode(allocator, self.redirect_uri, .url),
            try utils.urlEncode(allocator, state, .url),
            try utils.urlEncode(allocator, try std.mem.join(allocator, " ", scopes), .url),
        },
    );
}

pub fn createAuthorizationUrlWithPKCE(
    self: *const OAuth2Provider,
    allocator: std.mem.Allocator,
    authorization_endpoint: []const u8,
    state: []const u8,
    code_challenge_method: []const u8,
    code_verifier: []const u8,
    scopes: []const []const u8,
) ![]const u8 {
    return try std.fmt.allocPrint(
        allocator,
        "{s}?response_type=code&client_id={s}&redirect_uri={s}&state={s}&code_challenge_method={s}&code_challenge={s}&scope={s}",
        .{
            authorization_endpoint,
            try utils.urlEncode(allocator, self.client_id, .url),
            try utils.urlEncode(allocator, self.redirect_uri, .url),
            try utils.urlEncode(allocator, state, .url),
            code_challenge_method,
            try utils.urlEncode(allocator, try cryto.sha256Base64UrlSafe(allocator, code_verifier), .url),
            try utils.urlEncode(allocator, try std.mem.join(allocator, " ", scopes), .url),
        },
    );
}

pub fn validateAuthorizationCode(
    self: *const OAuth2Provider,
    comptime T: type,
    allocator: std.mem.Allocator,
    token_endpoint: []const u8,
    code: []const u8,
    code_verifier: ?[]const u8,
) !T {
    var form_data = std.StringHashMap([]const u8).init(allocator);
    defer form_data.deinit();

    try form_data.put("code", code);
    try form_data.put("client_id", self.client_id);
    try form_data.put("client_secret", self.client_secret);
    try form_data.put("redirect_uri", self.redirect_uri);
    try form_data.put("grant_type", "authorization_code");
    if (code_verifier) |verifier| try form_data.put("code_verifier", verifier);

    const body_data = try utils.formEncode(allocator, form_data);

    const oauth_token_response = try self.client.post(T, token_endpoint, body_data, try self.createBasicAuthHeader(allocator));
    defer oauth_token_response.deinit();

    return oauth_token_response.value;
}

pub fn refreshAccessToken(
    self: *const OAuth2Provider,
    comptime T: type,
    allocator: std.mem.Allocator,
    token_endpoint: []const u8,
    refresh_token: []const u8,
    scopes: ?[]const []const u8,
) !T {
    var form_data = std.StringHashMap([]const u8).init(allocator);
    defer form_data.deinit();

    try form_data.put("refresh_token", refresh_token);
    try form_data.put("client_id", self.client_id);
    try form_data.put("grant_type", "refresh_token");
    if (scopes) |s| try form_data.put("scope", try std.mem.join(allocator, " ", s));

    const body_data = try utils.formEncode(allocator, form_data);

    const oauth_token_response = try self.client.post(T, token_endpoint, body_data, try self.createBasicAuthHeader(allocator));
    defer oauth_token_response.deinit();

    return oauth_token_response.value;
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
    try form_data.put("client_secret", self.client_secret);

    const body_data = try utils.formEncode(allocator, form_data);

    const response = try self.client.post(void, token_revocation_endpoint, body_data, try self.createBasicAuthHeader(allocator));
    defer response.deinit();

    if (response != .ok) return error.HttpError;
}

fn createBasicAuthHeader(self: *const OAuth2Provider, allocator: std.mem.Allocator) ![]const u8 {
    const auth_string = try std.fmt.allocPrint(allocator, "{s}:{s}", .{ self.client_id, self.client_secret });
    const auth_encoded = try allocator.alloc(u8, std.base64.standard.Encoder.calcSize(auth_string.len));
    _ = std.base64.standard.Encoder.encode(auth_encoded, auth_string);

    return try std.fmt.allocPrint(allocator, "Basic {s}", .{auth_encoded});
}
