//
//  AuthConfiguration.swift
//  VLOAuthFlowCoordinator
//
//  Created by James Langdon on 11/23/25.
//

import Foundation

public struct AuthConfiguration {
    let clientKey: String
    let clientSecret: String
    let requestTokenUrl: URL
    let authorizationUrl: URL
    let accessTokenUrl: URL
    let callback: URL
    
    public init(
        clientKey: String,
        clientSecret: String,
        requestTokenUrl: URL,
        authorizationUrl: URL,
        accessTokenUrl: URL,
        callback: URL
    ) {
        self.clientKey = clientKey
        self.clientSecret = clientSecret
        self.requestTokenUrl = requestTokenUrl
        self.authorizationUrl = authorizationUrl
        self.accessTokenUrl = accessTokenUrl
        self.callback = callback
    }
    
    public init(
        clientCredentials: ClientCredentials,
        provider: OAuthProviderConfiguration,
        callback: URL
    ) {
        self.clientKey = clientCredentials.key
        self.clientSecret = clientCredentials.secret
        self.requestTokenUrl = provider.requestTokenUrl
        self.authorizationUrl = provider.authorizationUrl
        self.accessTokenUrl = provider.accessTokenUrl
        self.callback = callback
    }
}

public struct ClientCredentials {
    let key: String
    let secret: String
    
    public init(key: String, secret: String) {
        self.key = key
        self.secret = secret
    }
}

public protocol OAuthProviderConfiguration {
    var apiHost: String { get set }
    var requestTokenPath: String { get set }
    var accessTokenPath: String { get set }
    var authorizationUrl: String { get set }
}

extension OAuthProviderConfiguration {
    var apiHostUrl: URL {
        URL(string: apiHost)!
    }
    
    var authorizationUrl: URL {
        URL(string: authorizationUrl)!
    }
    
    var requestTokenUrl: URL {
        apiHostUrl.appending(path: requestTokenPath)
    }
    
    var accessTokenUrl: URL {
        apiHostUrl.appending(path: accessTokenPath)
    }
}
