//
//  AuthRequester.swift
//  VLOAuthFlowCoordinator
//
//  Created by James Langdon on 8/11/25.
//

import Foundation
import VLOAuthProvider
import SwiftUI
import WebKit
import AuthenticationServices
import VLDebugLogger
import Collections

/// Coordinates the OAuth 1.0a authentication flow, managing token storage and authentication sessions.
///
/// `OAuthFlowCoordinator` handles the complete three-legged OAuth flow:
/// 1. Requesting a temporary token from the server
/// 2. Presenting the authorization UI to the user
/// 3. Exchanging the authorized token for an access token
///
/// It supports both anonymous and account-specific token storage, allowing apps to maintain
/// tokens for multiple users or handle unauthenticated requests.
public class OAuthFlowCoordinator: NSObject, @unchecked Sendable {
    
    // MARK: - Constants
    
    /// The key used for storing tokens when no specific account is active
    private static let anonymousAccountKey: String = "anonymous"
    
    // MARK: - Dependencies
    
    /// Configuration containing OAuth endpoints and client credentials
    private let authConfiguration: AuthConfiguration
    
    /// Provider responsible for creating signed OAuth requests
    private let authenticationProvider: AuthenticationProvider
    
    /// Provider for making network requests and parsing OAuth responses
    private let networkProvider: NetworkProvider
    
    /// Logger instance for debugging OAuth flow
    private let logger: VLDebugLogger
    
    // MARK: - Token Storage
    
    /// Manages tokens for anonymous/unauthenticated requests
    private let anonymousTokenStorageManager: AccountTokenStorageManager
    
    /// Manages tokens for the currently active user account, if any
    private var activeAccountTokenStorageManager: AccountTokenStorageManager?
    
    // MARK: - Authentication Session
    
    /// The active web authentication session used during OAuth flow
    private var authSession: ASWebAuthenticationSession?
    
    /// Callback executed after successful authentication completes
    private var onSuccessfulAuthentication: (() async throws -> Void)?
    
    // MARK: - Computed Properties
    
    /// Returns the appropriate token manager based on whether an account is active
    /// - Returns: Active account token manager if available, otherwise anonymous token manager
    private var currentTokenManager: AccountTokenStorageManager {
        activeAccountTokenStorageManager ?? anonymousTokenStorageManager
    }
    
    /// The key identifying the currently active user account, if any
    public let activeAccountKey: String?
    
    // MARK: - Initialization
    
    /// Creates a new OAuth flow coordinator.
    ///
    /// - Parameters:
    ///   - authConfiguration: Configuration containing OAuth endpoints and client credentials
    ///   - authenticationProvider: Provider for creating signed OAuth requests (defaults to `OAuthProvider`)
    ///   - networkProvider: Provider for making network requests and parsing responses
    ///   - activeAccountKey: Optional key identifying the active user account
    ///   - onSuccessfulAuthentication: Optional callback executed after successful authentication
    ///   - logger: Logger instance for debugging (defaults to a new VLDebugLogger instance)
    public init(
        authConfiguration: AuthConfiguration,
        authenticationProvider: AuthenticationProvider = OAuthProvider(),
        networkProvider: NetworkProvider,
        activeAccountKey: String? = nil,
        onSuccessfulAuthentication: (() async throws -> Void)? = nil,
        logger: VLDebugLogger
    ) {
        self.authConfiguration = authConfiguration
        self.authenticationProvider = authenticationProvider
        self.networkProvider = networkProvider
        self.activeAccountKey = activeAccountKey
        self.onSuccessfulAuthentication = onSuccessfulAuthentication
        self.logger = logger
        if let activeAccountKey {
            self.activeAccountTokenStorageManager = AccountTokenStorageManager(tokenStorageManager: OAuthTokenStorageManager(keychainManager: DefaultKeychainManager()), accountKey: activeAccountKey)
            logger.log("Initialized OAuthFlowCoordinator with active account: \(activeAccountKey)", category: .oauth, level: .info)
        } else {
            logger.log("Initialized OAuthFlowCoordinator with anonymous account", category: .oauth, level: .info)
        }
        self.anonymousTokenStorageManager = AccountTokenStorageManager(tokenStorageManager: OAuthTokenStorageManager(keychainManager: DefaultKeychainManager()), accountKey: OAuthFlowCoordinator.anonymousAccountKey)
    }
    
    // MARK: - Public Methods
    
    /// Starts the complete OAuth 1.0a authentication flow.
    ///
    /// This method orchestrates the three-legged OAuth flow:
    /// 1. Fetches a request token from the server
    /// 2. Presents the authorization UI to the user
    /// 3. Exchanges the authorized token for an access token
    /// 4. Stores the access token for future use
    ///
    /// - Parameter prefersEphemeralWebBrowserSession: If `true`, requests that the browser not share cookies
    ///   or other browsing data between authentication sessions (defaults to `false`)
    /// - Throws: `OAuthFlowCooridnatorError` if any step of the flow fails
    public func startOAuthFlow(
        prefersEphemeralWebBrowserSession: Bool = false
    ) async throws {
        logger.log("Starting OAuth flow (ephemeral: \(prefersEphemeralWebBrowserSession))", category: .oauth, level: .info)
        
        do {
            // First leg - Request a temporary token
            logger.log("Step 1/4: Fetching request token", category: .oauth, level: .debug)
            let requestToken = try await fetchRequestToken()
            
            // Second leg - User authorization
            logger.log("Step 2/4: Building authorization URL", category: .oauth, level: .debug)
            let authorizationUrl = try await buildAuthorizationUrl(from: requestToken)
            
            logger.log("Step 3/4: Presenting authorization UI", category: .oauth, level: .debug)
            let verifier = try await authenticate(
                authorizationUrl,
                prefersEphemeralWebBrowserSession: prefersEphemeralWebBrowserSession
            )
            
            // Third leg - Exchange for an access token
            logger.log("Step 4/4: Exchanging verifier for access token", category: .oauth, level: .debug)
            let accessToken = try await getAccessToken(with: verifier)
            
            // Store access token for future requests
            try await storeAccessToken(accessToken)
            
            logger.log("OAuth flow completed successfully", category: .oauth, level: .info)
            
            // Call on success if provided
            try await onSuccessfulAuthentication?()
        } catch {
            logger.log(error, message: "OAuth flow failed", category: .oauth, level: .error)
            throw error
        }
    }
    
    /// Checks if the active account has valid stored tokens.
    ///
    /// - Returns: `true` if both access token and access token secret are present, `false` otherwise
    /// - Throws: Any keychain access errors
    public func activeAccountHasValidTokens() async throws -> Bool {
        let hasValidTokens = try await activeAccountTokenStorageManager?.hasValidTokens() ?? false
        logger.log("Active account valid tokens check: \(hasValidTokens)", category: .oauth, level: .debug)
        return hasValidTokens
    }
    
    /// Clears all stored tokens for the active account.
    ///
    /// - Throws: Any keychain deletion errors
    public func clearActiveTokens() async throws {
        logger.log("Clearing active account tokens", category: .oauth, level: .info)
        try await activeAccountTokenStorageManager?.clearTokens()
    }
    
    /// Clears all stored tokens for anonymous/unauthenticated requests.
    ///
    /// - Throws: Any keychain deletion errors
    public func clearAnonymousTokens() async throws {
        logger.log("Clearing anonymous tokens", category: .oauth, level: .info)
        try await anonymousTokenStorageManager.clearTokens()
    }
    
    /// Copies tokens from anonymous storage to the active account.
    ///
    /// This is useful when a user authenticates anonymously and then signs in,
    /// allowing their existing session to be transferred to their account.
    ///
    /// - Throws: Any keychain access or storage errors
    public func copyAnonymousTokensToActiveAccount() async throws {
        logger.log("Copying anonymous tokens to active account", category: .oauth, level: .info)
        if let accessToken = try await anonymousTokenStorageManager.getAccessToken(),
           let accessTokenSecret = try await anonymousTokenStorageManager.getAccessTokenSecret() {
            try await activeAccountTokenStorageManager?.saveAccessToken(accessToken)
            try await activeAccountTokenStorageManager?.saveAccessTokenSecret(accessTokenSecret)
            logger.log("Successfully copied anonymous tokens to active account", category: .oauth, level: .info)
        } else {
            logger.log("No anonymous tokens found to copy", category: .oauth, level: .warning)
        }
    }
    
    /// Retrieves the current access token from storage.
    ///
    /// - Returns: An `OAuthAccessToken` if both token and secret are present, `nil` otherwise
    /// - Throws: Any keychain access errors
    private func currentAccessToken() async throws -> OAuthAccessToken? {
        do {
            let currentAccessToken = try await currentTokenManager.getAccessToken()
            let currentAccessTokenSecret = try await currentTokenManager.getAccessTokenSecret()
            
            if let currentAccessToken, let currentAccessTokenSecret {
                return OAuthAccessToken(
                    token: currentAccessToken,
                    tokenSecret: currentAccessTokenSecret
                )
            }
        } catch {
            logger.log(error, message: "Unable to retrieve access tokens from keychain", category: .keychain, level: .error)
            return nil
        }
        return nil
    }
    
    /// Creates a signed OAuth request from the provided URL request.
    ///
    /// This method adds OAuth signature headers to the request using the stored access token
    /// for the current account (active or anonymous).
    ///
    /// - Parameters:
    ///   - request: The base URL request to sign
    ///   - user: Optional user identifier (currently unused)
    /// - Returns: A new URL request with OAuth signature headers added
    /// - Throws: Authentication errors if signing fails or tokens are missing
    public func getSignedRequest(from request: URLRequest, for user: String? = nil) async throws -> URLRequest {
        logger.log("Creating signed request for URL: \(request.url?.absoluteString ?? "unknown")", category: .oauth, level: .debug)
        let oAuthParameters = OAuthParameters(
            consumerKey: authConfiguration.clientKey,
            consumerSecret: authConfiguration.clientSecret,
            requestToken: try await currentAccessToken()?.token,
            requestSecret: try await currentAccessToken()?.tokenSecret,
            signatureMethod: .hmac
        )
        let signedRequest = try await authenticationProvider.createSignedRequest(
            from: request,
            with: oAuthParameters,
            as: .header
        )
        logger.log("Successfully created signed request", category: .oauth, level: .debug)
        return signedRequest
    }
    
    // MARK: - OAuth Flow Steps
    
    /// First leg of OAuth flow: Fetches a request token from the server.
    ///
    /// Creates a signed request to the request token endpoint and retrieves
    /// a temporary token that will be used in the authorization step.
    ///
    /// - Returns: An `OAuthRequestToken` containing the temporary token and secret
    /// - Throws: `OAuthFlowCooridnatorError.missingRequestToken` if the server doesn't return a token
    private func fetchRequestToken() async throws -> OAuthRequestToken {
        logger.log("Requesting temporary token from: \(authConfiguration.requestTokenUrl.absoluteString)", category: .oauth, level: .debug)
        
        let requestTokenRequest = URLRequest(url: authConfiguration.requestTokenUrl)
        let oAuthParameters = OAuthParameters(
            consumerKey: authConfiguration.clientKey,
            consumerSecret: authConfiguration.clientSecret,
            signatureMethod: .hmac,
            callback: authConfiguration.callback
        )
        let request = try await authenticationProvider.createSignedRequest(
            from: requestTokenRequest,
            with: oAuthParameters,
            as: .header
        )
        
        guard let requestToken = try await networkProvider.getRequestToken(from: request) else {
            logger.log(OAuthFlowCooridnatorError.missingRequestToken, message: "Failed to retrieve request token from server", category: .oauth, level: .error)
            throw OAuthFlowCooridnatorError.missingRequestToken
        }
        
        logger.log("Successfully fetched request token", category: .oauth, level: .info)
        return requestToken
    }
    
    /// Builds the authorization URL for the second leg of OAuth flow.
    ///
    /// Creates a signed URL that will be presented to the user for authorization.
    /// The request token secret is stored for later use in the access token exchange.
    ///
    /// - Parameter requestToken: The request token obtained from `fetchRequestToken()`
    /// - Returns: A URL that can be opened to present the authorization UI
    /// - Throws: `OAuthFlowCooridnatorError.malformedRequest` if the URL cannot be constructed
    private func buildAuthorizationUrl(
        from requestToken: OAuthRequestToken
    ) async throws -> URL {
        let requestTokenValue = requestToken.token
        let requestTokenSecretValue = requestToken.tokenSecret
        
        logger.log("Building authorization URL with request token", category: .oauth, level: .debug)
        
        try await currentTokenManager.saveRequestTokenSecret(requestTokenSecretValue)
        
        let authorizeRequest = URLRequest(url: authConfiguration.authorizationUrl)
        
        let oAuthParameters = OAuthParameters(
            consumerKey: authConfiguration.clientKey,
            consumerSecret: authConfiguration.clientSecret,
            requestToken: requestTokenValue,
            requestSecret: requestTokenSecretValue,
            signatureMethod: .hmac
        )
        
        let request = try await authenticationProvider.createSignedRequest(
            from: authorizeRequest,
            with: oAuthParameters,
            as: .queryString
        )
        
        guard let url = request.url else {
            logger.log(OAuthFlowCooridnatorError.malformedRequest, message: "Failed to construct authorization URL", category: .oauth, level: .error)
            throw OAuthFlowCooridnatorError.malformedRequest
        }
        
        logger.log("Built authorization URL: \(url.absoluteString)", category: .oauth, level: .info)
        return url
    }
    
    /// Second leg of OAuth flow: Presents the authorization UI to the user.
    ///
    /// Opens a web authentication session where the user can authorize the app.
    /// This method waits for the user to complete authorization and extracts the
    /// verifier from the callback URL.
    ///
    /// - Parameters:
    ///   - authorizationUrl: The URL to present for authorization
    ///   - prefersEphemeralWebBrowserSession: Whether to avoid sharing cookies between sessions
    /// - Returns: An `OAuthVerifier` containing the authorization code
    /// - Throws: Authentication errors or `OAuthFlowCooridnatorError.invalidCallbackUrl` if callback is invalid
    @MainActor
    private func authenticate(
        _ authorizationUrl: URL,
        prefersEphemeralWebBrowserSession: Bool
    ) async throws -> OAuthVerifier {
        let callbackScheme = authConfiguration.callback.scheme
        
        logger.log("Presenting authentication session", category: .oauth, level: .info)
        
        return try await withCheckedThrowingContinuation { continuation in
            authSession = ASWebAuthenticationSession(
                url: authorizationUrl,
                callbackURLScheme: callbackScheme
            ) { [weak self] callbackURL, error in
                guard let self else { return }
                if let error = error {
                    logger.log(error, message: "Authentication session failed", category: .oauth, level: .error)
                    continuation.resume(throwing: error)
                    return
                }
                do {
                    guard
                        let callbackURL = callbackURL,
                        callbackURL.scheme == callbackScheme,
                        callbackURL.host() == authConfiguration.callback.host(),
                        callbackURL.path() == authConfiguration.callback.path(),
                        let query = callbackURL.query(),
                        let oauthVerifier = try networkProvider.decodeVerifierResponse(from: query)
                    else {
                        logger.log(OAuthFlowCooridnatorError.invalidCallbackUrl, message: "Invalid callback URL received", category: .oauth, level: .error)
                        continuation.resume(throwing: OAuthFlowCooridnatorError.invalidCallbackUrl)
                        return
                    }
                    
                    logger.log("Successfully received authorization verifier", category: .oauth, level: .info)
                    continuation.resume(returning: oauthVerifier)
                } catch {
                    logger.log(error, message: "Failed to decode verifier response", category: .oauth, level: .error)
                    continuation.resume(throwing: error)
                }
            }
            
            authSession?.presentationContextProvider = self
            authSession?.prefersEphemeralWebBrowserSession = prefersEphemeralWebBrowserSession
            authSession?.start()
        }
    }
    
    /// Third leg of OAuth flow: Exchanges the verifier for an access token.
    ///
    /// Uses the authorization verifier obtained from the user to request
    /// a permanent access token from the server.
    ///
    /// - Parameter oauthVerifier: The verifier obtained after user authorization
    /// - Returns: An `OAuthAccessToken` containing the access token and secret
    /// - Throws: `OAuthFlowCooridnatorError.missingAccessToken` if the server doesn't return a token
    private func getAccessToken(with oauthVerifier: OAuthVerifier) async throws -> OAuthAccessToken {
        logger.log("Exchanging verifier for access token", category: .oauth, level: .debug)
        
        let oAuthParameters = OAuthParameters(
            consumerKey: authConfiguration.clientKey,
            consumerSecret: authConfiguration.clientSecret,
            requestToken: oauthVerifier.token,
            requestSecret: try await currentTokenManager.getRequestTokenSecret(),
            signatureMethod: .hmac,
            verifier: oauthVerifier.verifier
        )
        let request = try await authenticationProvider.createSignedRequest(
            from: URLRequest(url: authConfiguration.accessTokenUrl),
            with: oAuthParameters,
            as: .header
        )
        
        guard let accessToken = try await networkProvider.getAccessToken(from: request) else {
            logger.log(OAuthFlowCooridnatorError.missingAccessToken, message: "Failed to retrieve access token from server", category: .oauth, level: .error)
            throw OAuthFlowCooridnatorError.missingAccessToken
        }
        
        logger.log("Successfully obtained access token", category: .oauth, level: .info)
        return accessToken
    }
    
    /// Stores the access token in the keychain for future use.
    ///
    /// - Parameter accessToken: The access token to store
    /// - Throws: Keychain storage errors
    private func storeAccessToken(_ accessToken: OAuthAccessToken) async throws {
        logger.log("Storing access token in keychain", category: .oauth, level: .debug)
        try await currentTokenManager.saveAccessToken(accessToken.token)
        try await currentTokenManager.saveAccessTokenSecret(accessToken.tokenSecret)
        logger.log("Successfully stored access token", category: .oauth, level: .info)
    }

}

// MARK: - ASWebAuthenticationPresentationContextProviding

extension OAuthFlowCoordinator: ASWebAuthenticationPresentationContextProviding {
    /// Provides the presentation anchor (window) for the authentication session.
    ///
    /// This method is called by `ASWebAuthenticationSession` to determine which window
    /// should present the authentication UI.
    ///
    /// - Parameter session: The authentication session requesting a presentation anchor
    /// - Returns: The window that will present the authentication UI
    public func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        // Return your app's window
        if let windowScene = UIApplication.shared.connectedScenes
            .compactMap({ $0 as? UIWindowScene })
            .first {
            // First try to get an existing window
            if let window = windowScene.windows.first {
                return window
            }
            // Fallback to creating a new window with the window scene
            return ASPresentationAnchor(windowScene: windowScene)
        }
        
        // Fallback for when no window scene is available (shouldn't happen in normal circumstances)
        fatalError("Unable to find a valid UIWindowScene for presenting authentication")
    }
}
