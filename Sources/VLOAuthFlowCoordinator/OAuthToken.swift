//
//  OAuthToken.swift
//  VLOAuthFlowCoordinator
//
//  Created by James Langdon on 8/13/25.
//

import Foundation

public struct OAuthToken: Codable, Sendable {
    public let token: String
    public let tokenSecret: String
    public let callbackConfirmed: Bool
}
