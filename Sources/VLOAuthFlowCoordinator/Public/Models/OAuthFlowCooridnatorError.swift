//
//  OAuthFlowCooridnatorError.swift
//  VLOAuthFlowCoordinator
//
//  Created by James Langdon on 11/23/25.
//

import Foundation

enum OAuthFlowCooridnatorError: Error {
    case missingRequestToken
    case missingAccessToken
    case malformedRequest
    case invalidCallbackUrl
    case unknownConfiguration
    case keychainError
}
