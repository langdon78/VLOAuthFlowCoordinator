//
//  OAuthToken.swift
//  VLOAuthFlowCoordinator
//
//  Created by James Langdon on 8/13/25.
//

import Foundation

public struct OAuthRequestToken: Codable, Sendable {
    public let token: String
    public let tokenSecret: String
    public let callbackConfirmed: Bool
    
    public init(token: String, tokenSecret: String, callbackConfirmed: Bool) {
        self.token = token
        self.tokenSecret = tokenSecret
        self.callbackConfirmed = callbackConfirmed
    }
}

public struct OAuthVerifier: Codable, Sendable {
    public let token: String
    public let verifier: String
    
    public init(token: String, verifier: String) {
        self.token = token
        self.verifier = verifier
    }
}

public struct OAuthAccessToken: Codable, Sendable {
    public let token: String
    public let tokenSecret: String
    
    public init(token: String, tokenSecret: String) {
        self.token = token
        self.tokenSecret = tokenSecret
    }
}
