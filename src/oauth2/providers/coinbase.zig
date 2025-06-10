const std = @import("std");

const OAuth2Provider = @import("../oauth2.zig");
const OAuth2ProviderArgs = OAuth2Provider.OAuth2ProviderArgs;

const AUTHORIZATION_ENDPOINT = "https://login.coinbase.com/oauth2/auth";
const TOKEN_ENDPOINT = "https://login.coinbase.com/oauth2/token";
const TOKEN_REVOCATION_ENDPOINT = "https://login.coinbase.com/oauth2/revoke";

pub const CoinbaseTokenResponse = struct {
    access_token: []const u8,
    token_type: []const u8,
    expires_in: i64,
    refresh_token: ?[]const u8 = null,
    scope: []const u8,
};

const CoinbaseProvider = @This();

oauth2_provider: OAuth2Provider,

pub fn init(allocator: std.mem.Allocator, args: OAuth2ProviderArgs) !CoinbaseProvider {
    return CoinbaseProvider{
        .oauth2_provider = try OAuth2Provider.init(allocator, .{
            .client_id = args.client_id,
            .client_secret = args.client_secret,
            .redirect_uri = args.redirect_uri,
        }),
    };
}

pub fn deinit(self: *CoinbaseProvider) void {
    self.oauth2_provider.deinit();
}

pub fn createAuthorizationUrl(
    self: *const CoinbaseProvider,
    allocator: std.mem.Allocator,
    state: []const u8,
    scopes: []const []const u8,
) ![]const u8 {
    return self.oauth2_provider.createAuthorizationUrl(
        allocator,
        AUTHORIZATION_ENDPOINT,
        state,
        scopes,
    );
}

pub fn validateAuthorizationCode(
    self: *const CoinbaseProvider,
    allocator: std.mem.Allocator,
    code: []const u8,
) !CoinbaseTokenResponse {
    return self.oauth2_provider.validateAuthorizationCode(
        CoinbaseTokenResponse,
        allocator,
        TOKEN_ENDPOINT,
        code,
        null,
    );
}

pub fn refreshAccessToken(
    self: *const CoinbaseProvider,
    allocator: std.mem.Allocator,
    refresh_token: []const u8,
) !CoinbaseTokenResponse {
    return self.oauth2_provider.refreshAccessToken(
        CoinbaseTokenResponse,
        allocator,
        TOKEN_ENDPOINT,
        refresh_token,
    );
}

pub fn revokeAccessToken(
    self: *const CoinbaseProvider,
    allocator: std.mem.Allocator,
    access_token: []const u8,
) !void {
    return self.oauth2_provider.revokeAccessToken(
        allocator,
        TOKEN_REVOCATION_ENDPOINT,
        access_token,
    );
}
