const std = @import("std");

// Util functions
pub const generateStateOrCodeVerifier = @import("crypto.zig").generateStateOrCodeVerifier;

// OAuth2 Providers
pub const DiscordProvider = @import("oauth2/providers/discord.zig");
pub const GoogleProvider = @import("oauth2/providers/google.zig");
pub const LinkedInProvider = @import("oauth2/providers/linkedin.zig");

// Base OAuth2 provider for custom implementations
pub const BaseOAuth2Provider = @import("oauth2/oauth2.zig");

test {
    _ = @import("utils.zig");
    _ = @import("crypto.zig");
}
