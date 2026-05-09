//
//  OAuthFlowCoordinating.swift
//  VLOAuthFlowCoordinator
//
//  Created by James Langdon on 8/11/25.
//

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Defines the public interface for coordinating an OAuth 1.0a authentication flow.
///
/// Implementations manage the complete three-legged OAuth flow:
/// 1. Requesting a temporary token from the server
/// 2. Presenting the authorization UI to the user
/// 3. Exchanging the authorized token for an access token
///
/// Both anonymous and account-specific token storage are supported, allowing apps to maintain
/// tokens for multiple users or handle unauthenticated requests.
public protocol OAuthFlowCoordinating: AnyObject {

    /// The key identifying the currently active user account, if any.
    var activeAccountKey: String? { get }

    /// Starts the complete OAuth 1.0a authentication flow.
    ///
    /// Orchestrates the three-legged OAuth flow:
    /// 1. Fetches a request token from the server
    /// 2. Presents the authorization UI to the user
    /// 3. Exchanges the authorized token for an access token
    /// 4. Stores the access token for future use
    ///
    /// - Parameter prefersEphemeralWebBrowserSession: If `true`, requests that the browser not share
    ///   cookies or other browsing data between authentication sessions (defaults to `false`).
    /// - Throws: `OAuthFlowCooridnatorError` if any step of the flow fails.
    func startOAuthFlow(prefersEphemeralWebBrowserSession: Bool) async throws

    /// Checks if the active account has valid stored tokens.
    ///
    /// - Returns: `true` if both access token and access token secret are present, `false` otherwise.
    /// - Throws: Any keychain access errors.
    func activeAccountHasValidTokens() async throws -> Bool

    /// Clears all stored tokens for the active account.
    ///
    /// - Throws: Any keychain deletion errors.
    func clearActiveTokens() async throws

    /// Clears all stored tokens for anonymous/unauthenticated requests.
    ///
    /// - Throws: Any keychain deletion errors.
    func clearAnonymousTokens() async throws

    /// Copies tokens from anonymous storage to the active account.
    ///
    /// Useful when a user authenticates anonymously and then signs in,
    /// allowing their existing session to be transferred to their account.
    ///
    /// - Throws: Any keychain access or storage errors.
    func copyAnonymousTokensToActiveAccount() async throws

    /// Creates a signed OAuth request from the provided URL request.
    ///
    /// Adds OAuth signature headers to the request using the stored access token
    /// for the current account (active or anonymous).
    ///
    /// - Parameters:
    ///   - request: The base URL request to sign.
    ///   - user: Optional user identifier (currently unused).
    /// - Returns: A new URL request with OAuth signature headers added.
    /// - Throws: Authentication errors if signing fails or tokens are missing.
    func getSignedRequest(from request: URLRequest, for user: String?) async throws -> URLRequest
}
