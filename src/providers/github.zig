const std = @import("std");

const OAuth2Provider = @import("../oauth2.zig");
const OAuth2ProviderArgs = OAuth2Provider.OAuth2ProviderArgs;
const Param = OAuth2Provider.Param;
const Response = @import("../response.zig").Response;

const AUTHORIZATION_ENDPOINT = "https://github.com/login/oauth/authorize";
const TOKEN_ENDPOINT = "https://github.com/login/oauth/access_token";

pub const GitHubTokenResponse = struct {
    access_token: []const u8,
    token_type: []const u8,
    scope: []const u8,
};

const GitHubProvider = @This();

oauth2_provider: OAuth2Provider,

pub fn init(io: std.Io, allocator: std.mem.Allocator, args: OAuth2ProviderArgs) !GitHubProvider {
    return GitHubProvider{
        .oauth2_provider = try OAuth2Provider.init(io, allocator, .{
            .client_id = args.client_id,
            .client_secret = args.client_secret,
            .redirect_uri = args.redirect_uri,
        }),
    };
}

pub fn deinit(self: *GitHubProvider) void {
    self.oauth2_provider.deinit();
}

pub fn createAuthorizationUrl(
    self: *const GitHubProvider,
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
    self: *const GitHubProvider,
    allocator: std.mem.Allocator,
    code: []const u8,
    extra_params: []const Param,
) !Response(GitHubTokenResponse) {
    return self.oauth2_provider.validateAuthorizationCode(
        GitHubTokenResponse,
        allocator,
        TOKEN_ENDPOINT,
        code,
        null,
        extra_params,
    );
}

pub fn refreshAccessToken(
    self: *const GitHubProvider,
    allocator: std.mem.Allocator,
    refresh_token: []const u8,
    extra_params: []const Param,
) !Response(GitHubTokenResponse) {
    return self.oauth2_provider.refreshAccessToken(
        GitHubTokenResponse,
        allocator,
        TOKEN_ENDPOINT,
        refresh_token,
        null,
        extra_params,
    );
}
