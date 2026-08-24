// Util functions
pub const createStateNonce = @import("crypto.zig").createStateNonce;

// OAuth2 Providers
pub const BattleNetProvider = @import("providers/battlenet.zig");
pub const CoinbaseProvider = @import("providers/coinbase.zig");
pub const DiscordProvider = @import("providers/discord.zig");
pub const GoogleProvider = @import("providers/google.zig");
pub const GitHubProvider = @import("providers/github.zig");
pub const LinkedInProvider = @import("providers/linkedin.zig");

// Base OAuth2 provider for custom implementations
pub const BaseOAuth2Provider = @import("oauth2.zig");
pub const Response = @import("response.zig").Response;

test {
    _ = @import("utils.zig");
    _ = @import("crypto.zig");
    _ = @import("http.zig");
    _ = @import("response.zig");
    _ = @import("oauth2.zig");
}
