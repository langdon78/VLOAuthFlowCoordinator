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

public class OAuthFlowCoordinator: NSObject, @unchecked Sendable {
    private let authConfiguration: AuthConfiguration
    private let authenticationProvider: AuthenticationProvider
    private let networkProvider: NetworkProvider
    private let oauthTokenStorageManager: MultiUserOAuthTokenStorageManager = MultiUserOAuthTokenStorageManager(tokenStorageManager: OAuthTokenStorageManager(keychainManager: DefaultKeychainManager()))
    private var authSession: ASWebAuthenticationSession?
    private var onSuccessfulAuthentication: (() async throws -> Void)?
    
    public init(
        authConfiguration: AuthConfiguration,
        authenticationProvider: AuthenticationProvider = OAuthProvider(),
        networkProvider: NetworkProvider,
        onSuccessfulAuthentication: (() async throws -> Void)? = nil
    ) {
        self.authConfiguration = authConfiguration
        self.authenticationProvider = authenticationProvider
        self.networkProvider = networkProvider
        self.onSuccessfulAuthentication = onSuccessfulAuthentication
    }
    
    public func startOAuthFlow(
        prefersEphemeralWebBrowserSession: Bool = false
    ) async throws {
        // First leg - Request a temporary token
        let requestToken = try await fetchRequestToken()
        
        // Second leg - User authorization
        let authorizationUrl = try await buildAuthorizationUrl(from: requestToken)
        let verifier = try await authenticate(
            authorizationUrl,
            prefersEphemeralWebBrowserSession: prefersEphemeralWebBrowserSession
        )
        
        // Third leg - Exchange for an access token
        let accessToken = try await getAccessToken(with: verifier)
        
        // Store access token for future requests
        try storeAccessToken(accessToken)
        
        // Call on success if provided
        try await onSuccessfulAuthentication?()
    }
    
    public func hasValidTokens(for user: String) -> Bool {
        oauthTokenStorageManager.hasValidTokens(for: user)
    }
    
    public func clearTokens(for user: String) -> Bool {
        oauthTokenStorageManager.clearAllTokens(for: user)
    }
    
    public func saveTokens(for user: String) throws {
        try oauthTokenStorageManager.saveAccessTokens(for: user)
    }
    
    public func getSignedRequest(from request: URLRequest, for user: String? = nil) async throws -> URLRequest {
        var accessToken = oauthTokenStorageManager.getAccessToken(for: user)
        var accessTokenSecret = oauthTokenStorageManager.getAccessTokenSecret(for: user)

        let oAuthParameters = OAuthParameters(
            consumerKey: authConfiguration.clientKey,
            consumerSecret: authConfiguration.clientSecret,
            requestToken: accessToken,
            requestSecret: accessTokenSecret,
            signatureMethod: .hmac
        )
        return try await authenticationProvider.createSignedRequest(
            from: request,
            with: oAuthParameters,
            as: .header
        )
    }
    
    private func fetchRequestToken() async throws -> OAuthRequestToken {
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
            throw OAuthFlowCooridnatorError.missingRequestToken
        }
        return requestToken
    }
    
    private func buildAuthorizationUrl(
        from requestToken: OAuthRequestToken
    ) async throws -> URL {
        let requestTokenValue = requestToken.token
        let requestTokenSecretValue = requestToken.tokenSecret
        
        let tokenSecretDidSave = oauthTokenStorageManager.saveRequestTokenSecret(requestTokenSecretValue)
        if !tokenSecretDidSave {
            throw OAuthFlowCooridnatorError.keychainError
        }
        
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
        
        guard let url = request.url else { throw OAuthFlowCooridnatorError.malformedRequest }
        return url
    }
    
    @MainActor
    private func authenticate(
        _ authorizationUrl: URL,
        prefersEphemeralWebBrowserSession: Bool
    ) async throws -> OAuthVerifier {
        let callbackScheme = authConfiguration.callback.scheme
        
        return try await withCheckedThrowingContinuation { continuation in
            authSession = ASWebAuthenticationSession(
                url: authorizationUrl,
                callbackURLScheme: callbackScheme
            ) { [weak self] callbackURL, error in
                if let error = error {
                    continuation.resume(throwing: error)
                    return
                }
                do {
                    guard
                        let self,
                        let callbackURL = callbackURL,
                        callbackURL.scheme == callbackScheme,
                        callbackURL.host() == authConfiguration.callback.host(),
                        callbackURL.path() == authConfiguration.callback.path(),
                        let query = callbackURL.query(),
                        let oauthVerifier = try networkProvider.decodeVerifierResponse(from: query)
                    else {
                        continuation.resume(throwing: OAuthFlowCooridnatorError.invalidCallbackUrl)
                        return
                    }
                    
                    continuation.resume(returning: oauthVerifier)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
            
            authSession?.presentationContextProvider = self
            authSession?.prefersEphemeralWebBrowserSession = prefersEphemeralWebBrowserSession
            authSession?.start()
        }
    }
    
    private func getAccessToken(with oauthVerifier: OAuthVerifier) async throws -> OAuthAccessToken {
        let oAuthParameters = OAuthParameters(
            consumerKey: authConfiguration.clientKey,
            consumerSecret: authConfiguration.clientSecret,
            requestToken: oauthVerifier.token,
            requestSecret: oauthTokenStorageManager.getRequestTokenSecret(),
            signatureMethod: .hmac,
            verifier: oauthVerifier.verifier
        )
        let request = try await authenticationProvider.createSignedRequest(
            from: URLRequest(url: authConfiguration.accessTokenUrl),
            with: oAuthParameters,
            as: .header
        )
        
        guard let accessToken = try await networkProvider.getAccessToken(from: request) else {
            throw OAuthFlowCooridnatorError.missingAccessToken
        }
        
        return accessToken
    }
    
    private func storeAccessToken(_ accessToken: OAuthAccessToken) throws {
        let accessTokenDidSave = oauthTokenStorageManager.saveAccessToken(accessToken.token)
        let accessTokenSecretDidSave = oauthTokenStorageManager.saveAccessTokenSecret(accessToken.tokenSecret)
        if !(accessTokenDidSave && accessTokenSecretDidSave) {
            throw OAuthFlowCooridnatorError.keychainError
        }
    }

}

extension OAuthFlowCoordinator: ASWebAuthenticationPresentationContextProviding {
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
