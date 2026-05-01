# oauth2.zig

A light weight oauth2 wrapper for zig. Contains implementations for the authorization code flow with no external dependencies.

## Installation

Add oauth2.zig as a dependency to your project with:

```sh
zig fetch --save git+https://github.com/aw1875/oauth2.zig
```

Then, add it as a dependency in your `build.zig` file:

```zig
const oauth2 = b.dependency("oauth2", .{ .target = target, .optimize = optimize });
exe.root_module.addImport("oauth2", oauth2.module("oauth2"));
```

## Supported Providers

This is a work in progress, but currently supports the following providers:
- [BattleNet](https://develop.battle.net/documentation/guides/using-oauth)
- [Coinbase](https://docs.cdp.coinbase.com/coinbase-app/docs/auth/oauth-integration)
- [Discord](https://discord.com/developers/docs/topics/oauth2)
- [GitHub](https://docs.github.com/en/developers/apps/building-oauth-apps/authorizing-oauth-apps)
- [Google](https://developers.google.com/identity/protocols/oauth2)
- [LinkedIn](https://docs.microsoft.com/en-us/linkedin/shared/authentication/authorization-code-flow)

The BaseOAuth2Provider is also exposed, which allows you to create your own custom provider by directly accessing the underlying OAuth2 functions used by each provider. See [CustomProvider](#custom-provider)

## Examples

Check out the [examples folder](./examples) for a few examples of how to use the library with different providers.

#### Custom Provider

We'll use Google here for clarity, but the `BaseOAuth2Provider` just exposes all the underlying functions used by any given individual provider.
One important thing to note, depending on your provider you may need to use the `createAuthorizationUrlWithPKCE` version when creating your authorization URL.
The `code_verifier` is only required for providers that require this (Google is a great example):

```zig
const std = @import("std");

const httpz = @import("httpz");
const oauth2 = @import("oauth2");

const CustomProvider = oauth2.BaseOAuth2Provider;

const SessionData = struct {
    state: []const u8,
    code_verifier: []const u8,
    expires_at: i128,
};

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const allocator = init.gpa;

    var oauth2_provider = try CustomProvider.init(io, allocator, .{
        .client_id = "<google_client_id>",
        .client_secret = "<google_client_secret>",
        .redirect_uri = "http://localhost:3000/api/v1/oauth/google/callback",
    });
    defer oauth2_provider.deinit();

    var session_store = std.StringHashMap(SessionData).init(allocator);
    defer session_store.deinit();

    var app = App{ .io = io, .oauth = &oauth2_provider, .session_store = &session_store };

    var server = try httpz.Server(*App).init(allocator, .{ .port = 3000 }, &app);
    defer {
        server.stop();
        server.deinit();
    }

    var router = try server.router(.{});
    router.get("/api/v1/oauth/google", handleLogin, .{});
    router.get("/api/v1/oauth/google/callback", handleCallback, .{});

    try server.listen();
}

const App = struct {
    io: std.Io,
    oauth: *CustomProvider,
    session_store: *std.StringHashMap(SessionData),
};

fn handleLogin(app: *App, _: *httpz.Request, res: *httpz.Response) !void {
    const state = try oauth2.createStateNonce(app.io, res.arena);
    const code_verifier = try oauth2.createStateNonce(app.io, res.arena);
    const url = try app.oauth.createAuthorizationUrlWithPKCE(
        res.arena,
        "https://accounts.google.com/o/oauth2/v2/auth",
        state,
        "S256",
        code_verifier,
        &[_][]const u8{ "email", "profile", "openid" },
    );

    const session_id = try oauth2.createStateNonce(app.io, res.arena);
    try app.session_store.put(session_id, SessionData{
        .state = state,
        .code_verifier = code_verifier,
        .expires_at = @intCast(std.Io.Clock.now(.real, app.io).nanoseconds + (60 * 5 * 1000 * std.time.ns_per_ms)), // 5 minutes
    });

    try res.setCookie("example.sid", session_id, .{ .path = "/", .secure = true, .http_only = true, .max_age = 60 * 5 }); // Session ID cookie

    res.headers.add("Location", url);
    res.setStatus(.found);
}

fn handleCallback(app: *App, req: *httpz.Request, res: *httpz.Response) !void {
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

    if (std.Io.Clock.now(.real, app.io).nanoseconds > session_data.value.expires_at) {
        std.log.err("Session expired for ID: {s}", .{session_id});
        return res.setStatus(.unauthorized);
    }

    if (!std.mem.eql(u8, state, session_data.value.state)) {
        std.log.err("State mismatch: expected {s}, got {s}", .{ session_data.value.state, state });
        return res.setStatus(.bad_request);
    }

    return res.json(try app.oauth.validateAuthorizationCode(GoogleTokenResponse, res.arena, "https://oauth2.googleapis.com/token", code, session.code_verifier), .{});
}

// This is the response we expect to get back when validating the authorization code
pub const GoogleTokenResponse = struct {
    access_token: []const u8,
    expires_in: i64,
    refresh_token: ?[]const u8 = null,
    scope: []const u8,
    token_type: []const u8,
    id_token: []const u8,
};
```
