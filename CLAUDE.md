# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```sh
swift build
swift test
swift test --filter VLOAuthFlowCoordinatorTests
```

## What this is

Orchestrates the OAuth 1.0a three-legged flow (request token → user authorization via `ASWebAuthenticationSession` → access token exchange) and manages Keychain-backed token storage. Depends on `VLOAuthProvider` for the actual signature generation and `VLDebugLogger` for logging. This is the layer `VLDiscogsClient` uses to get from "user taps sign in" to "have a working, signed API session" — it does not itself know about Discogs specifically (it's configured per-provider via `AuthConfiguration`/`OAuthProviderConfiguration`).

This package has no knowledge of `VLNetworkingClient` or its `Interceptor` protocol either — it does not wire itself into a request pipeline. `VLDiscogsClient` is the one that adapts `getSignedRequest(from:for:)` into a `VLNetworkingClient`-conformant `Interceptor` (its own private `OAuthInterceptor`/`OAuthTokenManager`) and injects it into the chain. If you're tracing how a Discogs request actually gets signed end-to-end, that adapter code lives in `VLDiscogsClient`, not here.

## Architecture

- **`OAuthFlowCoordinating`** (protocol, `Public/OAuthFlowCoordinating.swift`) — the public contract. `OAuthFlowCoordinator` is the concrete implementation.
- **`AuthConfiguration`** — consumer key/secret + the three provider endpoint URLs (request token, authorization, access token) + callback URL. Two initializers: raw URLs, or via an `OAuthProviderConfiguration` (a small protocol you implement per API provider — see `VLDiscogsClient`'s `DiscogsOAuthProvider`).
- **Multi-account support is real, not incidental.** Tokens are stored keyed by `accountKey` (`AccountTokenStorageManager`), and there's a distinct "anonymous" storage bucket alongside named accounts, with `copyAnonymousTokensToActiveAccount()` / `clearAnonymousTokens()` / `clearActiveTokens()` as separate operations. If you're debugging a token-not-found issue, check which bucket (anonymous vs. a specific `accountKey`) the code is actually reading from before assuming tokens are missing entirely.
- **Token storage is Keychain-backed** (`DefaultKeychainManager`, `OAuthTokenStorageManager`) and stores access token, access token secret, and (transiently, mid-flow) the request token secret.

### There is no getter for the raw access token/secret — this is deliberate, not a gap to work around

The full public surface for reading auth state is: `activeAccountKey: String?` (just an identifying key, not a credential), `activeAccountHasValidTokens() -> Bool`, and `getSignedRequest(from:for:) -> URLRequest`. There is no method anywhere that returns the actual token or token secret string. **Do not go looking for one, and do not add one to work around a design problem elsewhere** — if a consumer needs to prove Discogs authentication to a third-party service, the design has to work within "you can get a signed request or a yes/no on validity," not "you can extract the credential." (This exact gap is why VLOrganizer's Supabase auth bridge uses Sign in with Apple instead of relaying a Discogs token — see VLOrganizer's ADR-005.)

### `getSignedRequest(from:for:)` signs *any* request, not just requests to the configured provider

It takes an arbitrary `URLRequest` and returns it with OAuth signature headers added from the stored credentials — there's no host restriction at this layer. Two things worth knowing if you're tempted to use this for something creative:

1. A restriction you might hit elsewhere (e.g. `VLDiscogsClient.request()` being hardcoded to Discogs's API host) is a decision made at that higher layer, not a limitation here.
2. Signing an arbitrary request with Discogs OAuth credentials does **not** make that signature independently verifiable by a third party that isn't Discogs — OAuth 1.0a signature verification requires the shared consumer secret, which only your app and Discogs hold. Don't reach for this method thinking it lets some other service (e.g. a Supabase Edge Function) confirm "yes, this is a real Discogs session" — it can't, without either Discogs's secret or Discogs itself doing the verification.

### Errors

`OAuthFlowCooridnatorError` (note the typo in the actual type name — `Cooridnator`, not `Coordinator`) covers flow failures. Don't "fix" the typo without checking whether it's used as a string key anywhere (e.g. in tests or serialized error identifiers) that would break on rename.
