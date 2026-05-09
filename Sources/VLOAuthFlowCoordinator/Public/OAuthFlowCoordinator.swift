//
//  AuthRequester.swift
//  VLOAuthFlowCoordinator
//
//  Created by James Langdon on 8/11/25.
//

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import VLOAuthProvider
import VLDebugLogger
import Collections
#if canImport(AuthenticationServices)
import AuthenticationServices
#endif

public class OAuthFlowCoordinator: NSObject, OAuthFlowCoordinating, @unchecked Sendable {

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

#if canImport(AuthenticationServices)
    /// The active web authentication session used during OAuth flow
    private var authSession: ASWebAuthenticationSession?
#endif

    /// Callback executed after successful authentication completes
    private var onSuccessfulAuthentication: (() async throws -> Void)?

    // MARK: - Computed Properties

    /// Returns the appropriate token manager based on whether an account is active
    private var currentTokenManager: AccountTokenStorageManager {
        activeAccountTokenStorageManager ?? anonymousTokenStorageManager
    }

    /// The key identifying the currently active user account, if any
    public let activeAccountKey: String?

    // MARK: - Initialization

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

    public func startOAuthFlow(
        prefersEphemeralWebBrowserSession: Bool = false
    ) async throws {
        logger.log("Starting OAuth flow (ephemeral: \(prefersEphemeralWebBrowserSession))", category: .oauth, level: .info)

        do {
            logger.log("Step 1/4: Fetching request token", category: .oauth, level: .debug)
            let requestToken = try await fetchRequestToken()

            logger.log("Step 2/4: Building authorization URL", category: .oauth, level: .debug)
            let authorizationUrl = try await buildAuthorizationUrl(from: requestToken)

            logger.log("Step 3/4: Presenting authorization UI", category: .oauth, level: .debug)
            let verifier = try await authenticate(
                authorizationUrl,
                prefersEphemeralWebBrowserSession: prefersEphemeralWebBrowserSession
            )

            logger.log("Step 4/4: Exchanging verifier for access token", category: .oauth, level: .debug)
            let accessToken = try await getAccessToken(with: verifier)

            try await storeAccessToken(accessToken)

            logger.log("OAuth flow completed successfully", category: .oauth, level: .info)

            try await onSuccessfulAuthentication?()
        } catch {
            logger.log(error, message: "OAuth flow failed", category: .oauth, level: .error)
            throw error
        }
    }

    public func activeAccountHasValidTokens() async throws -> Bool {
        let hasValidTokens = try await activeAccountTokenStorageManager?.hasValidTokens() ?? false
        logger.log("Active account valid tokens check: \(hasValidTokens)", category: .oauth, level: .debug)
        return hasValidTokens
    }

    public func clearActiveTokens() async throws {
        logger.log("Clearing active account tokens", category: .oauth, level: .info)
        try await activeAccountTokenStorageManager?.clearTokens()
    }

    public func clearAnonymousTokens() async throws {
        logger.log("Clearing anonymous tokens", category: .oauth, level: .info)
        try await anonymousTokenStorageManager.clearTokens()
    }

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

#if canImport(AuthenticationServices)
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
#else
    private func authenticate(
        _ authorizationUrl: URL,
        prefersEphemeralWebBrowserSession: Bool
    ) async throws -> OAuthVerifier {
        throw OAuthFlowCooridnatorError.invalidCallbackUrl
    }
#endif

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

    private func storeAccessToken(_ accessToken: OAuthAccessToken) async throws {
        logger.log("Storing access token in keychain", category: .oauth, level: .debug)
        try await currentTokenManager.saveAccessToken(accessToken.token)
        try await currentTokenManager.saveAccessTokenSecret(accessToken.tokenSecret)
        logger.log("Successfully stored access token", category: .oauth, level: .info)
    }

}

// MARK: - ASWebAuthenticationPresentationContextProviding

#if canImport(AuthenticationServices)
extension OAuthFlowCoordinator: ASWebAuthenticationPresentationContextProviding {
    public func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
#if canImport(UIKit)
        if let windowScene = UIApplication.shared.connectedScenes
            .compactMap({ $0 as? UIWindowScene })
            .first {
            if let window = windowScene.windows.first {
                return window
            }
            return ASPresentationAnchor(windowScene: windowScene)
        }
        fatalError("Unable to find a valid UIWindowScene for presenting authentication")
#else
        fatalError("Interactive OAuth flow is not supported in server context; use pre-stored tokens.")
#endif
    }
}
#endif
