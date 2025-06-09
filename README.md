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
- [Discord](https://discord.com/developers/docs/topics/oauth2)
- [Google](https://developers.google.com/identity/protocols/oauth2)
- [LinkedIn](https://docs.microsoft.com/en-us/linkedin/shared/authentication/authorization-code-flow)

The BaseOAuth2Provider is also exposed, which allows you to create your own custom provider by directly accessing the underlying OAuth2 functions used by each provider. See [CustomProvider](#custom-provider)

## Examples

All examples will use [http.zig](https://github.com/karlseguin/http.zig) as our server. The same logic can be applied anywhere though.
Please note that the examples don't handle any memory cleanup because we're letting httpz's response arena allocator handle all allocations and deallocations.
If your use case differs, you will want to handle deallocation appropriately to avoid memory leaks.

#### GoogleProvider

```zig
const std = @import("std");

const httpz = @import("httpz");
const oauth2 = @import("oauth2");

const GoogleProvider = oauth2.GoogleProvider;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    defer if (gpa.deinit() != .ok) @panic("Failed to deinitialize allocator");

    var oauth2_provider = try GoogleProvider.init(allocator, .{
        .client_id = "<google_client_id>",
        .client_secret = "<google_client_secret>",
        .redirect_uri = "http://localhost:3000/api/v1/oauth/google/callback",
    });
    defer oauth2_provider.deinit();

    var app = App{
        .oauth = &oauth2_provider,
    };

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
    oauth: *GoogleProvider,
};

fn handleLogin(app: *App, _: *httpz.Request, res: *httpz.Response) !void {
    const state = try oauth2.generateStateOrCodeVerifier(res.arena);
    const code_verifier = try oauth2.generateStateOrCodeVerifier(res.arena);
    const url = try app.oauth.createAuthorizationUrl(res.arena, state, code_verifier, &[_][]const u8{ "email", "profile", "openid" });

    try res.setCookie("example.gos", state, .{ .path = "/", .secure = true, .http_only = true, .max_age = 60 * 5 }); // Google OAuth "State" cookie
    try res.setCookie("example.goc", code_verifier, .{ .path = "/", .secure = true, .http_only = true, .max_age = 60 * 5 }); // Google OAuth "Code Verifier" cookie

    res.headers.add("Location", url);
    res.setStatus(.permanent_redirect);
}

fn handleCallback(app: *App, req: *httpz.Request, res: *httpz.Response) !void {
    const query = try req.query();

    if (query.get("error") != null) {
        std.debug.print("OAuth Error: {s}\n", .{query.get("error").?});
        return res.setStatus(.internal_server_error);
    }

    const code = query.get("code") orelse return res.setStatus(.internal_server_error); // Missing code parameter
    const state = query.get("state") orelse return res.setStatus(.internal_server_error); // Missing state parameter
    const state_cookie = req.cookies().get("example_app.gos") orelse return res.setStatus(.bad_request); // Missing state cookie
    const code_verifier_cookie = req.cookies().get("example_app.goc") orelse return res.setStatus(.bad_request); // Missing code verifier cookie
    if (!std.mem.eql(u8, state, state_cookie)) return res.setStatus(.bad_request); // State mismatch

    // It might make sense to get the user's info here in your project rather than returning the auth information
    return res.json(try app.oauth.validateAuthorizationCode(res.arena, code, code_verifier_cookie), .{});
}
```

#### Custom Provider

We'll use Google again here for consistency sake, but the `BaseOAuth2Provider` just exposes all the underlying functions used by any given individual provider.
One important thing to note, depending on your provider you may need to use the `createAuthorizationUrlWithPKCE` version when creating your authorization URL.
The `code_verifier` is only required for providers that require this (Google is a great example):

```zig
const std = @import("std");

const httpz = @import("httpz");
const oauth2 = @import("oauth2");

const CustomProvider = oauth2.BaseOAuth2Provider;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    defer if (gpa.deinit() != .ok) @panic("Failed to deinitialize allocator");

    var oauth2_provider = try CustomProvider.init(allocator, .{
        .client_id = "<google_client_id>",
        .client_secret = "<google_client_secret>",
        .redirect_uri = "http://localhost:3000/api/v1/oauth/google/callback",
    });
    defer oauth2_provider.deinit();

    var app = App{
        .oauth = &oauth2_provider,
    };

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
    oauth: *CustomProvider,
};

fn handleLogin(app: *App, _: *httpz.Request, res: *httpz.Response) !void {
    const state = try oauth2.generateStateOrCodeVerifier(res.arena);
    const code_verifier = try oauth2.generateStateOrCodeVerifier(res.arena);
    const url = try app.oauth.createAuthorizationUrlWithPKCE(
        res.arena,
        "https://accounts.google.com/o/oauth2/v2/auth",
        state,
        "S256",
        code_verifier,
        &[_][]const u8{ "email", "profile", "openid" },
    );

    try res.setCookie("example.gos", state, .{ .path = "/", .secure = true, .http_only = true, .max_age = 60 * 5 }); // Google OAuth "State" cookie
    try res.setCookie("example.goc", code_verifier, .{ .path = "/", .secure = true, .http_only = true, .max_age = 60 * 5 }); // Google OAuth "Code Verifier" cookie

    res.headers.add("Location", url);
    res.setStatus(.permanent_redirect);
}

fn handleCallback(app: *App, req: *httpz.Request, res: *httpz.Response) !void {
    const query = try req.query();

    if (query.get("error") != null) {
        std.debug.print("OAuth error: {s}\n", .{query.get("error").?});
        return res.setStatus(.internal_server_error);
    }

    const code = query.get("code") orelse return res.setStatus(.internal_server_error); // Missing code parameter
    const state = query.get("state") orelse return res.setStatus(.internal_server_error); // Missing state parameter
    const state_cookie = req.cookies().get("example_app.gos") orelse return res.setStatus(.bad_request); // Missing state cookie
    const code_verifier_cookie = req.cookies().get("example_app.goc") orelse return res.setStatus(.bad_request); // Missing code verifier cookie
    if (!std.mem.eql(u8, state, state_cookie)) return res.setStatus(.bad_request); // State mismatch

    return res.json(try app.oauth.validateAuthorizationCode(GoogleTokenResponse, res.arena, "https://oauth2.googleapis.com/token", code, code_verifier_cookie), .{});
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

#### Getting the user's profile

This example will take our first example with [GoogleProvider](#googleprovider) one step further by getting and returning the user's profile:

```zig
...everything from our first example

fn handleCallback(app: *App, req: *httpz.Request, res: *httpz.Response) !void {
    const query = try req.query();

    if (query.get("error") != null) {
        std.debug.print("OAuth error: {s}\n", .{query.get("error").?});
        return res.setStatus(.internal_server_error);
    }

    const code = query.get("code") orelse return res.setStatus(.internal_server_error); // Missing code parameter
    const state = query.get("state") orelse return res.setStatus(.internal_server_error); // Missing state parameter
    const state_cookie = req.cookies().get("example_app.gos") orelse return res.setStatus(.bad_request); // Missing state cookie
    const code_verifier_cookie = req.cookies().get("example_app.goc") orelse return res.setStatus(.bad_request); // Missing code verifier cookie
    if (!std.mem.eql(u8, state, state_cookie)) return res.setStatus(.bad_request); // State mismatch

    const tokens = try app.oauth.validateAuthorizationCode(res.arena, code, code_verifier_cookie);
    const user_profile = try getUserProfile(res.arena, "https://www.googleapis.com/oauth2/v3/userinfo", tokens.access_token);
    defer user_profile.deinit();

    return res.json(user_profile.value, .{});
}

// Adding this helper function to reach out to Google using the provided bearer token (our access_token)
fn getUserProfile(allocator: std.mem.Allocator, url: []const u8, access_token: []const u8) !std.json.Parsed(GoogleUserProfile) {
    var http_client = std.http.Client{ .allocator = allocator };
    defer http_client.deinit();

    var server_header_buffer: [1024 * 1024 * 4]u8 = undefined;
    var req = try http_client.open(.GET, try std.Uri.parse(url), .{ .server_header_buffer = &server_header_buffer });
    defer req.deinit();

    req.headers.accept_encoding = .{ .override = "application/json" };
    req.extra_headers = &[_]std.http.Header{.{ .name = "Authorization", .value = try std.fmt.allocPrint(allocator, "Bearer {s}", .{access_token}) }};

    try req.send();
    try req.finish();
    try req.wait();

    if (req.response.status != .ok) return error.HttpError;

    const response_data = try req.reader().readAllAlloc(allocator, 1024 * 1024 * 4);
    defer allocator.free(response_data);

    return try std.json.parseFromSlice(GoogleUserProfile, allocator, response_data, .{ .allocate = .alloc_always, .ignore_unknown_fields = true });
}

// An example of the Goole Profile structure
const GoogleUserProfile = struct {
    sub: []const u8,
    email: []const u8,
    email_verified: bool,
    name: []const u8,
    given_name: []const u8,
    family_name: []const u8,
    picture: []const u8,
};
```
