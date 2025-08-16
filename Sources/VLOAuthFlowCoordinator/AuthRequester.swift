//
//  AuthRequester.swift
//  VLOAuthFlowCoordinator
//
//  Created by James Langdon on 8/11/25.
//

import VLNetworkingClient
import Foundation
import VLOAuthProvider
import SwiftUI
import WebKit

public class AuthRequester: @unchecked Sendable {
    private let authConfiguration: AuthConfiguration
    private let asyncNetworkClient: AsyncNetworkClientProtocol
    private let authenticationProvider: AuthenticationProvider
    
    public init(
        authConfiguration: AuthConfiguration,
        asyncNetworkClient: AsyncNetworkClientProtocol = AsyncNetworkClient(),
        authenticationProvider: AuthenticationProvider = OAuthProvider()
    ) {
        self.authConfiguration = authConfiguration
        self.asyncNetworkClient = asyncNetworkClient
        self.authenticationProvider = authenticationProvider
    }
    
    func startAuthFlow() {
        
    }
    
    public func requestToken() async throws -> NetworkResponse<OAuthToken> {
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
        let requestConfiguration = RequestConfiguration(
            url: request.url!,
            headers: request.allHTTPHeaderFields ?? [:]
        )
        let response: NetworkResponse<OAuthToken> = try await asyncNetworkClient.request(for: requestConfiguration, with: TokenResponseDecoder())
        return response
    }
    
    public func authorize(requestToken: String, requestSecret: String) async throws -> URLRequest {
        let authorizeRequest = URLRequest(url: authConfiguration.authorizeUrl)
        let oAuthParameters = OAuthParameters(
            consumerKey: authConfiguration.clientKey,
            consumerSecret: authConfiguration.clientSecret,
            requestToken: requestToken,
            requestSecret: requestSecret,
            signatureMethod: .hmac
        )
        let request = try await authenticationProvider.createSignedRequest(
            from: authorizeRequest,
            with: oAuthParameters,
            as: .queryString
        )
        return request
    }
    
    func accessToken(for authorizeResponse: String) {
        
    }
}

public struct AuthConfiguration {
    public let clientKey: String
    public let clientSecret: String
    public let requestTokenUrl: URL
    public let authorizeUrl: URL
    public let accessTokenUrl: URL
    public let callback: URL
    
    public init(
        clientKey: String,
        clientSecret: String,
        requestTokenUrl: URL,
        authorizeUrl: URL,
        accessTokenUrl: URL,
        callback: URL
    ) {
        self.clientKey = clientKey
        self.clientSecret = clientSecret
        self.requestTokenUrl = requestTokenUrl
        self.authorizeUrl = authorizeUrl
        self.accessTokenUrl = accessTokenUrl
        self.callback = callback
    }
}

struct ContentView: View {
    let authConfiguration = AuthConfiguration(
        clientKey: "2NVVBip7I5kfl0TwVmGzTphhC98kmXScpZaoz7ET",
        clientSecret: "wXzb8tGqXNbBQ5juA0ZKuFAmSW7RwOw8uSbdE3MvbrI8wjcbGp",
        requestTokenUrl: URL(string: "http://localhost:5001/oauth/request_token")!,
        authorizeUrl: URL(string: "http://localhost:5001/oauth/authorize")!,
        accessTokenUrl: URL(string: "http://localhost:5001/oauth/access_token")!,
        callback: URL(string: "http://localhost:8080")!
    )
    @State var url: URL?
    
    var body: some View {
        WebView(url: url)
            .task {
                do {
                    let authRequester = AuthRequester(authConfiguration: authConfiguration)
                    let oauthToken = try await authRequester.requestToken().data
                    url = try await authRequester.authorize(requestToken: oauthToken!.token, requestSecret: oauthToken!.tokenSecret).url
                } catch {
                    print(error)
                }
            }
    }
}

#Preview {
    ContentView()
}
