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
    private let oauthTokenStorageManager: OAuthTokenStorageManager
    private var authSession: ASWebAuthenticationSession?
    private var onSuccessfulAuthentication: (() async throws -> Void)?
    
    public init(
        authConfiguration: AuthConfiguration,
        authenticationProvider: AuthenticationProvider = OAuthProvider(),
        networkProvider: NetworkProvider,
        oauthTokenStorageManager: OAuthTokenStorageManager = OAuthTokenStorageManager(),
        onSuccessfulAuthentication: (() async throws -> Void)? = nil
    ) {
        self.authConfiguration = authConfiguration
        self.authenticationProvider = authenticationProvider
        self.networkProvider = networkProvider
        self.oauthTokenStorageManager = oauthTokenStorageManager
        self.onSuccessfulAuthentication = onSuccessfulAuthentication
    }
    
    public func startOAuthFlow() async throws {
        // First leg - Request a temporary token
        let requestToken = try await fetchRequestToken()
        
        // Second leg - User authorization
        let authorizationUrl = try await buildAuthorizationUrl(from: requestToken)
        let verifier = try await authenticate(authorizationUrl)
        
        // Third leg - Exchange for an access token
        let accessToken = try await getAccessToken(with: verifier)
        
        // Store access token for future requests
        await storeAccessToken(accessToken)
        
        // Call on success if provided
        try await onSuccessfulAuthentication?()
    }
    
    public func hasValidTokens() -> Bool {
        oauthTokenStorageManager.hasValidTokens()
    }
    
    public func clearToken() {
        oauthTokenStorageManager.clearAllTokens()
    }
    
    public func getSignedRequest(from request: URLRequest) async throws -> URLRequest {
        let oAuthParameters = await OAuthParameters(
            consumerKey: authConfiguration.clientKey,
            consumerSecret: authConfiguration.clientSecret,
            requestToken: oauthTokenStorageManager.getAccessToken(),
            requestSecret: oauthTokenStorageManager.getAccessTokenSecret(),
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
        
        oauthTokenStorageManager.saveRequestTokenSecret(requestTokenSecretValue)
        
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
    private func authenticate(_ authorizationUrl: URL) async throws -> OAuthVerifier {
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
            authSession?.prefersEphemeralWebBrowserSession = true
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
    
    private func storeAccessToken(_ accessToken: OAuthAccessToken) async {
        oauthTokenStorageManager.saveAccessToken(accessToken.token)
        oauthTokenStorageManager.saveAccessTokenSecret(accessToken.tokenSecret)
    }

}

extension OAuthFlowCoordinator: ASWebAuthenticationPresentationContextProviding {
    public func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        // Return your app's window
        UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .first?.windows.first ?? ASPresentationAnchor()
    }
}
