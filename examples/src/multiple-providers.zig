const std = @import("std");

const httpz = @import("httpz");
const oauth2 = @import("oauth2");

const DiscordProvider = oauth2.DiscordProvider;
const GitHubProvider = oauth2.GitHubProvider;

const SessionData = struct {
    state: []const u8,
    expires_at: i64,
};

const OAuthProvider = enum {
    discord,
    github,
    unknown,
};

const TokenResponse = union(enum) {
    discord: oauth2.DiscordProvider.DiscordTokenResponse,
    github: oauth2.GitHubProvider.GitHubTokenResponse,
};

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const allocator = init.gpa;

    var discord_oauth2_provider = try DiscordProvider.init(io, allocator, .{
        .client_id = "<your_client_id>",
        .client_secret = "<your_client_secret>",
        .redirect_uri = "http://localhost:3000/api/v1/oauth/discord/callback",
    });

    var github_oauth2_provider = try GitHubProvider.init(io, allocator, .{
        .client_id = "<your_client_id>",
        .client_secret = "<your_client_secret>",
        .redirect_uri = "http://localhost:3000/api/v1/oauth/github/callback",
    });
    var session_store = std.StringHashMap(SessionData).init(allocator);

    defer {
        discord_oauth2_provider.deinit();
        github_oauth2_provider.deinit();
        session_store.deinit();
    }

    var app = App{
        .io = io,
        .discord = &discord_oauth2_provider,
        .github = &github_oauth2_provider,
        .session_store = &session_store,
    };

    var server = try httpz.Server(*App).init(io, allocator, .{ .address = .localhost(3000) }, &app);
    defer {
        server.stop();
        server.deinit();
    }

    var router = try server.router(.{});
    router.get("/", handleRoot, .{});
    router.get("/api/v1/oauth/:provider", handleLogin, .{});
    router.get("/api/v1/oauth/:provider/callback", handleCallback, .{});

    std.log.info("Running Multiple Providers example project on port 3000", .{});
    try server.listen();
}

const App = struct {
    io: std.Io,
    discord: *DiscordProvider,
    github: *GitHubProvider,
    session_store: *std.StringHashMap(SessionData),
};

fn handleRoot(_: *App, _: *httpz.Request, res: *httpz.Response) !void {
    return res.json(.{
        .discord = "http://localhost:3000/api/v1/oauth/discord",
        .github = "http://localhost:3000/api/v1/oauth/github",
    }, .{});
}

fn handleLogin(app: *App, req: *httpz.Request, res: *httpz.Response) !void {
    const provider = req.params.get("provider") orelse return res.setStatus(.bad_request);

    const state = try oauth2.createStateNonce(app.io, res.arena);
    const url = switch (std.meta.stringToEnum(OAuthProvider, provider) orelse OAuthProvider.unknown) {
        .discord => try app.discord.createAuthorizationUrl(res.arena, state, &[_][]const u8{ "identify", "email" }),
        .github => try app.github.createAuthorizationUrl(res.arena, state, &[_][]const u8{ "read:user", "user:email" }),
        .unknown => return res.setStatus(.not_found),
    };

    const session_id = try oauth2.createStateNonce(app.io, res.arena);
    try app.session_store.put(session_id, SessionData{
        .state = state,
        .expires_at = @intCast(std.Io.Clock.now(.real, app.io).toMilliseconds() + (60 * 5 * 1000)), // 5 minutes
    });

    try res.setCookie("example.sid", session_id, .{ .path = "/", .secure = true, .http_only = true, .max_age = 60 * 5 }); // Session ID cookie

    res.headers.add("Location", url);
    res.setStatus(.found);
}

fn handleCallback(app: *App, req: *httpz.Request, res: *httpz.Response) !void {
    const provider = req.params.get("provider") orelse return res.setStatus(.bad_request);
    const query = try req.query();

    if (query.get("error") != null) {
        std.log.err("OAuth Error: {s}", .{query.get("error").?});
        return res.setStatus(.internal_server_error);
    }

    const code = query.get("code") orelse {
        std.log.err("Missing 'code' parameter in OAuth callback.", .{});
        return res.setStatus(.internal_server_error);
    };

    const state = query.get("state") orelse {
        std.log.err("Missing 'state' parameter in OAuth callback.", .{});
        return res.setStatus(.internal_server_error);
    };

    const session_id = req.cookies().get("example.sid") orelse {
        std.log.err("Missing 'session ID' cookie in OAuth callback.", .{});
        return res.setStatus(.bad_request);
    };

    try res.setCookie("example.sid", "", .{ .path = "/", .secure = true, .http_only = true, .max_age = 0 }); // Clear session ID cookie

    const session_data = app.session_store.fetchRemove(session_id) orelse {
        std.log.err("Invalid session ID: {s}", .{session_id});
        return res.setStatus(.bad_request);
    };

    if (std.Io.Clock.now(.real, app.io).toMilliseconds() > session_data.value.expires_at) {
        std.log.err("Session expired for ID: {s}", .{session_id});
        return res.setStatus(.unauthorized);
    }

    if (!std.mem.eql(u8, state, session_data.value.state)) {
        std.log.err("State mismatch: expected {s}, got {s}", .{ session_data.value.state, state });
        return res.setStatus(.bad_request);
    }

    const tokens: TokenResponse = switch (std.meta.stringToEnum(OAuthProvider, provider) orelse OAuthProvider.unknown) {
        .discord => .{ .discord = try app.discord.validateAuthorizationCode(res.arena, code) },
        .github => .{ .github = try app.github.validateAuthorizationCode(res.arena, code) },
        .unknown => return res.setStatus(.not_found),
    };

    const user_profile = switch (std.meta.stringToEnum(OAuthProvider, provider) orelse OAuthProvider.unknown) {
        .discord => try getUserProfile(app.io, res.arena, "https://discord.com/api/users/@me", tokens.discord.access_token),
        .github => try getUserProfile(app.io, res.arena, "https://api.github.com/user", tokens.github.access_token),
        .unknown => return res.setStatus(.not_found),
    };

    return res.json(user_profile.value, .{});
}

fn getUserProfile(io: std.Io, allocator: std.mem.Allocator, url: []const u8, access_token: []const u8) !std.json.Parsed(std.json.Value) {
    var http_client = std.http.Client{ .allocator = allocator, .io = io };
    defer http_client.deinit();

    var body_writer: std.Io.Writer.Allocating = .init(allocator);
    defer body_writer.deinit();

    const response = try http_client.fetch(.{
        .location = .{ .url = url },
        .method = .GET,
        .headers = .{
            .authorization = .{ .override = try std.fmt.allocPrint(allocator, "Bearer {s}", .{access_token}) },
        },
        .extra_headers = &[_]std.http.Header{
            .{ .name = "User-Agent", .value = "oauth2.zig" },
            .{ .name = "Accept", .value = "application/json" },
        },
        .response_writer = &body_writer.writer,
    });

    if (response.status != .ok) return error.HttpError;

    const body = try body_writer.toOwnedSlice();
    defer allocator.free(body);

    return try std.json.parseFromSlice(std.json.Value, allocator, body, .{ .allocate = .alloc_always, .ignore_unknown_fields = true });
}
