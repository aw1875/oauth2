const std = @import("std");

const OAuth2Provider = @import("../oauth2.zig");
const OAuth2ProviderArgs = OAuth2Provider.OAuth2ProviderArgs;
const Param = OAuth2Provider.Param;
const Response = @import("../response.zig").Response;

const AUTHORIZATION_ENDPOINT = "https://oauth.battle.net/authorize";
const TOKEN_ENDPOINT = "https://oauth.battle.net/token";

pub const BattleNetTokenResponse = struct {
    access_token: []const u8,
    token_type: []const u8,
    expires_in: i64,
    scope: []const u8,
};

const BattleNetProvider = @This();

oauth2_provider: OAuth2Provider,

pub fn init(io: std.Io, allocator: std.mem.Allocator, args: OAuth2ProviderArgs) !BattleNetProvider {
    return BattleNetProvider{
        .oauth2_provider = try OAuth2Provider.init(io, allocator, .{
            .client_id = args.client_id,
            .client_secret = args.client_secret,
            .redirect_uri = args.redirect_uri,
        }),
    };
}

pub fn deinit(self: *BattleNetProvider) void {
    self.oauth2_provider.deinit();
}

pub fn createAuthorizationUrl(
    self: *const BattleNetProvider,
    allocator: std.mem.Allocator,
    state: []const u8,
    scopes: []const []const u8,
    extra_params: []const Param,
) ![]const u8 {
    return self.oauth2_provider.createAuthorizationUrl(
        allocator,
        AUTHORIZATION_ENDPOINT,
        state,
        scopes,
        extra_params,
    );
}

pub fn validateAuthorizationCode(
    self: *const BattleNetProvider,
    allocator: std.mem.Allocator,
    code: []const u8,
    extra_params: []const Param,
) !Response(BattleNetTokenResponse) {
    return self.oauth2_provider.validateAuthorizationCode(
        BattleNetTokenResponse,
        allocator,
        TOKEN_ENDPOINT,
        code,
        null,
        extra_params,
    );
}

pub fn refreshAccessToken(
    self: *const BattleNetProvider,
    allocator: std.mem.Allocator,
    refresh_token: []const u8,
    extra_params: []const Param,
) !Response(BattleNetTokenResponse) {
    return self.oauth2_provider.refreshAccessToken(
        BattleNetTokenResponse,
        allocator,
        TOKEN_ENDPOINT,
        refresh_token,
        null,
        extra_params,
    );
}
