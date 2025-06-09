const std = @import("std");

const OAuth2Provider = @import("../oauth2.zig");
const OAuth2ProviderArgs = OAuth2Provider.OAuth2ProviderArgs;

const AUTHORIZATION_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";
const TOKEN_REVOCATION_ENDPOINT = "https://oauth2.googleapis.com/revoke";

pub const GoogleTokenResponse = struct {
    access_token: []const u8,
    expires_in: i64,
    refresh_token: ?[]const u8 = null,
    scope: []const u8,
    token_type: []const u8,
    id_token: []const u8,
};

const GoogleProvider = @This();

oauth2_provider: OAuth2Provider,

pub fn init(allocator: std.mem.Allocator, args: OAuth2ProviderArgs) !GoogleProvider {
    return GoogleProvider{
        .oauth2_provider = try OAuth2Provider.init(allocator, .{
            .client_id = args.client_id,
            .client_secret = args.client_secret,
            .redirect_uri = args.redirect_uri,
        }),
    };
}

pub fn deinit(self: *GoogleProvider) void {
    self.oauth2_provider.deinit();
}

pub fn createAuthorizationUrl(
    self: *const GoogleProvider,
    allocator: std.mem.Allocator,
    state: []const u8,
    code_verifier: []const u8,
    scopes: []const []const u8,
) ![]const u8 {
    return self.oauth2_provider.createAuthorizationUrlWithPKCE(
        allocator,
        AUTHORIZATION_ENDPOINT,
        state,
        "S256",
        code_verifier,
        scopes,
    );
}

pub fn validateAuthorizationCode(
    self: *const GoogleProvider,
    allocator: std.mem.Allocator,
    code: []const u8,
    code_verifier: ?[]const u8,
) !GoogleTokenResponse {
    return self.oauth2_provider.validateAuthorizationCode(
        GoogleTokenResponse,
        allocator,
        TOKEN_ENDPOINT,
        code,
        code_verifier,
    );
}

pub fn refreshAccessToken(
    self: *const GoogleProvider,
    allocator: std.mem.Allocator,
    refresh_token: []const u8,
) !GoogleTokenResponse {
    return self.oauth2_provider.refreshAccessToken(
        GoogleTokenResponse,
        allocator,
        TOKEN_ENDPOINT,
        refresh_token,
    );
}

pub fn revokeAccessToken(
    self: *const GoogleProvider,
    allocator: std.mem.Allocator,
    access_token: []const u8,
) !void {
    return self.oauth2_provider.revokeAccessToken(
        allocator,
        TOKEN_REVOCATION_ENDPOINT,
        access_token,
    );
}
